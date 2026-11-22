use super::canonical::{decode_hex_32, hex_encode, sha256_bytes};
use std::cmp::Ordering;

pub const DSSE_PAYLOAD_TYPE_V2: &str = "application/vnd.r5e.provenance-evidence+json;v=2";

const ED25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const ED25519_SMALL_ORDER_Y_HEX: [&str; 5] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

const P256_ORDER_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P384_ORDER_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

fn decode_hex_exact<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    if hex_str.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn shr_one_be<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut carry = 0u8;
    for i in 0..N {
        let next_carry = (input[i] & 1) << 7;
        out[i] = (input[i] >> 1) | carry;
        carry = next_carry;
    }
    out
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn encode_uvarint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

pub fn is_registered_algorithm(alg: &str) -> bool {
    matches!(alg, "ed25519" | "es256" | "es384")
}

/// §2.3 public key admissibility check, run before trusting any key id or signature.
pub fn is_key_admissible(alg: &str, pk: &[u8]) -> bool {
    match alg {
        "ed25519" => {
            let Ok(karr) = <&[u8; 32]>::try_from(pk) else {
                return false;
            };
            let mut y = *karr;
            y[31] &= 0x7f;
            // 1. y < 2^255 - 19
            if y.iter().rev().cmp(ED25519_P_LE.iter().rev()) != Ordering::Less {
                return false;
            }
            // 2. Not a small-order point encoding
            for hex_row in ED25519_SMALL_ORDER_Y_HEX {
                let small = decode_hex_32(hex_row).expect("constant hex");
                if y == small {
                    return false;
                }
            }
            // 3. Point lies on the Edwards25519 curve (`(y^2 - 1)/(d*y^2 + 1) mod p` is a square).
            // Since rules 1 and 2 already rejected y >= p and the only roots of y^2 - 1 == 0 (y = 1, p - 1),
            // decompression succeeds if and only if rule 3 holds.
            ed25519_dalek::VerifyingKey::from_bytes(karr).is_ok()
        }
        "es256" => pk.len() == 65 && pk[0] == 0x04 && p256::PublicKey::from_sec1_bytes(pk).is_ok(),
        "es384" => pk.len() == 97 && pk[0] == 0x04 && p384::PublicKey::from_sec1_bytes(pk).is_ok(),
        _ => false,
    }
}

/// §2.3 Key id: `key:<alg>:sha256:<hex>` where digest is SHA-256 of
/// `uvarint(len(alg)) || alg || public key bytes`.
/// Returns `None` if `alg` is unregistered or `pk` is inadmissible.
pub fn compute_keyid(alg: &str, pk: &[u8]) -> Option<String> {
    if !is_key_admissible(alg, pk) {
        return None;
    }
    let mut preimage = Vec::with_capacity(1 + alg.len() + pk.len());
    encode_uvarint(alg.len(), &mut preimage);
    preimage.extend_from_slice(alg.as_bytes());
    preimage.extend_from_slice(pk);
    let digest = sha256_bytes(&preimage);
    Some(format!("key:{alg}:sha256:{}", hex_encode(&digest)))
}

/// §2.4 DSSE Pre-Authentication Encoding.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// §2.3 Signature verification with strict length, range, and low-S rules.
pub fn verify_signature(alg: &str, pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    if !is_key_admissible(alg, pk) {
        return false;
    }
    match alg {
        "ed25519" => {
            if sig.len() != 64 {
                return false;
            }
            if sig[32..64].iter().rev().cmp(ED25519_L_LE.iter().rev()) != Ordering::Less {
                return false;
            }
            let Ok(karr) = <&[u8; 32]>::try_from(pk) else {
                return false;
            };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(karr) else {
                return false;
            };
            let Ok(signature) = ed25519_dalek::Signature::from_slice(sig) else {
                return false;
            };
            ed25519_dalek::Verifier::verify(&vk, msg, &signature).is_ok()
        }
        "es256" => {
            if sig.len() != 64 {
                return false;
            }
            let r = &sig[0..32];
            let s = &sig[32..64];
            let n: [u8; 32] = decode_hex_exact(P256_ORDER_HEX).expect("constant P-256 order");
            let n_half = shr_one_be(&n);
            if is_all_zero(r) || r >= n.as_slice() {
                return false;
            }
            if is_all_zero(s) || s > n_half.as_slice() {
                return false;
            }
            let Ok(pubkey) = p256::PublicKey::from_sec1_bytes(pk) else {
                return false;
            };
            let vk = p256::ecdsa::VerifyingKey::from(pubkey);
            let Ok(signature) = p256::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            p256::ecdsa::signature::Verifier::verify(&vk, msg, &signature).is_ok()
        }
        "es384" => {
            if sig.len() != 96 {
                return false;
            }
            let r = &sig[0..48];
            let s = &sig[48..96];
            let n: [u8; 48] = decode_hex_exact(P384_ORDER_HEX).expect("constant P-384 order");
            let n_half = shr_one_be(&n);
            if is_all_zero(r) || r >= n.as_slice() {
                return false;
            }
            if is_all_zero(s) || s > n_half.as_slice() {
                return false;
            }
            let Ok(pubkey) = p384::PublicKey::from_sec1_bytes(pk) else {
                return false;
            };
            let vk = p384::ecdsa::VerifyingKey::from(pubkey);
            let Ok(signature) = p384::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            p384::ecdsa::signature::Verifier::verify(&vk, msg, &signature).is_ok()
        }
        _ => false,
    }
}

pub fn merkle_leaf_hash(digest_32: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = 0x00;
    buf[1..33].copy_from_slice(digest_32);
    sha256_bytes(&buf)
}

pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256_bytes(&buf)
}

/// §2.6 RFC 9162 §2.1 Merkle tree hash over 32-byte evidence digests.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256_bytes(&[]),
        1 => merkle_leaf_hash(&leaves[0]),
        n => {
            let k = 1usize << ((usize::BITS - 1 - (n - 1).leading_zeros()) as usize);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            merkle_node_hash(&left, &right)
        }
    }
}

/// §2.6 RFC 9162 §2.1.3.2 Merkle inclusion proof verification.
/// `siblings` is ordered from the leaf upward and every sibling must be consumed.
pub fn verify_inclusion_proof(
    leaf_digest: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    let mut fn_idx = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = merkle_leaf_hash(leaf_digest);

    for p in siblings {
        if sn == 0 {
            return false;
        }
        if (fn_idx & 1) == 1 || fn_idx == sn {
            r = merkle_node_hash(p, &r);
            if (fn_idx & 1) == 0 {
                while (fn_idx & 1) == 0 && fn_idx != 0 {
                    fn_idx >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = merkle_node_hash(&r, p);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    sn == 0 && &r == expected_root
}
