#![allow(clippy::field_reassign_with_default)]

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use r5e_verify_rs::provenance_v2::{
    VerifyOptions,
    canonical::{
        bytes_ref_of, decode_base64, decode_strict_base64, encode_canonical_json, evidence_ref_of,
        hex_encode, parse_canonical_json, strict_json_parse,
    },
    crypto::{
        DSSE_PAYLOAD_TYPE_V2, compute_keyid, dsse_pae, merkle_leaf_hash, merkle_node_hash,
        merkle_root, verify_inclusion_proof, verify_signature,
    },
    definition::ParsedDefinition,
    verify_bundle_bytes, verify_bundle_value,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_TMP: AtomicUsize = AtomicUsize::new(0);

fn vectors_cases_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("R5E_PROVENANCE_VECTORS_DIR") {
        return PathBuf::from(dir).join("cases");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join("r5e-spec")
        .join("cases")
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "r5e-v2-edge-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestKey {
    sk: SigningKey,
    pk: [u8; 32],
    keyid: String,
}

impl TestKey {
    fn from_seed(byte: u8) -> Self {
        let sk = SigningKey::from_bytes(&[byte; 32]);
        let pk = sk.verifying_key().to_bytes();
        let keyid = compute_keyid("ed25519", &pk).expect("valid ed25519 key");
        Self { sk, pk, keyid }
    }

    fn key_json(&self) -> Value {
        json!({
            "keyid": self.keyid,
            "algorithm": "ed25519",
            "bytes": STANDARD.encode(self.pk),
        })
    }

    fn sign_payload(&self, payload_bytes: &[u8]) -> Value {
        let msg = dsse_pae(DSSE_PAYLOAD_TYPE_V2, payload_bytes);
        let sig = self.sk.sign(&msg).to_bytes();
        json!({
            "keyid": self.keyid,
            "sig": STANDARD.encode(sig),
        })
    }
}

fn make_blob(val: &Value) -> (String, Value) {
    let bytes = encode_canonical_json(val).unwrap().into_bytes();
    let r = bytes_ref_of(&bytes);
    (
        r.clone(),
        json!({
            "ref": r,
            "base64": STANDARD.encode(&bytes),
        }),
    )
}

fn make_signed_record(payload: &Value, signers: &[&TestKey]) -> (String, Value) {
    let payload_bytes = encode_canonical_json(payload).unwrap().into_bytes();
    let rec_ref = evidence_ref_of(&payload_bytes);
    let sigs: Vec<Value> = signers
        .iter()
        .map(|k| k.sign_payload(&payload_bytes))
        .collect();
    (
        rec_ref.clone(),
        json!({
            "ref": rec_ref,
            "envelope": {
                "payloadType": DSSE_PAYLOAD_TYPE_V2,
                "payload": STANDARD.encode(&payload_bytes),
                "signatures": sigs,
            }
        }),
    )
}

fn make_profile(schemas: Value, issuer_kids: &[&str], sealer_kids: &[&str]) -> (String, Value) {
    let dummy_policy = bytes_ref_of(b"policy");
    let prof = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [{
                "streamPrefix": "stream:",
                "actorPrefixes": ["actor:"],
                "issuerKeys": issuer_kids,
                "sealerKeys": sealer_kids,
            }],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "node",
            "requiredPayloads": "submitted",
            "onFailure": "refuse",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": dummy_policy,
    });
    make_blob(&prof)
}

fn empty_bundle_with(
    records: Vec<Value>,
    blobs: Vec<Value>,
    keys: Vec<Value>,
    seals: Vec<Value>,
    proofs: Vec<Value>,
) -> Value {
    json!({
        "format": "r5e.provenance-export/v2",
        "scope": { "query": {}, "at": [] },
        "records": records,
        "blobs": blobs,
        "keys": keys,
        "seals": seals,
        "checkpoints": [],
        "proofs": proofs,
        "publicationProofs": [],
        "omissions": [],
    })
}

#[test]
fn canonical_json_rules_escapes_bounds_duplicates_and_non_bmp_keys() {
    // Control character short escapes (\b \t \n \f \r), \u00xx lowercase, unescaped '/', raw UTF-8
    let v = json!({
        "b": "\x08\t\n\x0c\r\x00\x1f/\"\\é😀",
        "a": [-9007199254740991_i64, 0, 9007199254740991_i64]
    });
    let enc = encode_canonical_json(&v).unwrap();
    assert_eq!(
        enc,
        "{\"a\":[-9007199254740991,0,9007199254740991],\"b\":\"\\b\\t\\n\\f\\r\\u0000\\u001f/\\\"\\\\é😀\"}"
    );
    assert_eq!(parse_canonical_json(enc.as_bytes()).unwrap(), v);

    // Non-BMP key (> U+FFFF) is rejected in canonical JSON, while BMP non-ASCII keys sort by UTF-8/UTF-16 identically
    assert!(encode_canonical_json(&json!({"😀": 1})).is_none());
    assert!(parse_canonical_json("{\"😀\":1}".as_bytes()).is_none());
    let bmp = json!({"\u{FFFE}": 2, "\u{00E9}": 1});
    let bmp_enc = encode_canonical_json(&bmp).unwrap();
    assert_eq!(parse_canonical_json(bmp_enc.as_bytes()).unwrap(), bmp);

    // Duplicate keys (literal and escaped), -0, floats, exponents, and out-of-range integers rejected
    for bad in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"a":-0}"#,
        r#"{"a":-0.0}"#,
        r#"{"a":1.0}"#,
        r#"{"a":1e2}"#,
        r#"{"a":9007199254740992}"#,
        r#"{"a":-9007199254740992}"#,
        r#"{"a":"\/"}"#,
        r#"{"a":"\u000a"}"#,
        r#"{"a":"\u001F"}"#,
        r#"{"a":"\ud83d\ude00"}"#,
    ] {
        assert!(
            parse_canonical_json(bad.as_bytes()).is_none(),
            "expected canonical rejection for {bad}"
        );
    }

    // Outer bundle parser (§3) rejects duplicate keys (exit 2), while RFC 8259
    // numbers outside §2.1 (`-0`, floats, big ints) pass §3 parse and fail schema (`malformed_bundle`, exit 1).
    assert!(strict_json_parse(br#"{"a":1,"a":2}"#).is_none());
    assert!(strict_json_parse(br#"{"a":-0}"#).is_some());
    assert!(verify_bundle_bytes(br#"{"a":1,"a":1}"#, &VerifyOptions::default()).is_err());
    let neg_zero_report = verify_bundle_bytes(
        br#"{"format":"r5e.provenance-export/v2","records":[],"blobs":[],"keys":[],"seals":[],"proofs":[{"record":"evidence:sha256:0000000000000000000000000000000000000000000000000000000000000000","seal":"evidence:sha256:0000000000000000000000000000000000000000000000000000000000000000","index":-0,"siblings":[]}],"omissions":[]}"#,
        &VerifyOptions::default(),
    )
    .expect("RFC 8259 -0 in outer bundle parses under §3 and reaches schema");
    assert_eq!(neg_zero_report.exit_code(false), 1);
    assert_eq!(neg_zero_report.findings[0].code, "malformed_bundle");
}

#[test]
fn base64_and_crypto_edge_cases() {
    // Non-zero trailing pad bits (`AB==` vs `AA==`) fail with `invalid_base64`
    assert_eq!(decode_base64(""), Some(vec![]));
    assert!(decode_strict_base64("").is_none());
    assert_eq!(decode_strict_base64("AA=="), Some(vec![0]));
    assert!(decode_base64("AB==").is_none());
    assert!(decode_strict_base64("AB==").is_none());

    // Ed25519 small-order points with sign bit 0 and sign bit 1 have no keyid
    let mut small_signed = [0u8; 32];
    small_signed[0] = 1;
    small_signed[31] = 0x80;
    assert!(compute_keyid("ed25519", &small_signed).is_none());

    // Compressed SEC1 P-256 (33 bytes) and P-384 (49 bytes) rejected even if valid curve point
    assert!(compute_keyid("es256", &[0x02; 33]).is_none());
    assert!(compute_keyid("es384", &[0x03; 49]).is_none());

    // Ed25519 S >= L rejected
    let k = TestKey::from_seed(7);
    let msg = b"hello";
    let mut sig = k.sk.sign(msg).to_bytes();
    assert!(verify_signature("ed25519", &k.pk, &sig, msg));
    sig[32..64].fill(0xff);
    assert!(!verify_signature("ed25519", &k.pk, &sig, msg));

    // ES256 and ES384 valid low-S signatures accepted, high-S (`n - s`) rejected
    fn sub_be<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
        let mut out = [0u8; N];
        let mut borrow = 0i16;
        for i in (0..N).rev() {
            let diff = (a[i] as i16) - (b[i] as i16) - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        out
    }
    fn decode_hex_arr<const N: usize>(h: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    let sk256 = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let pk256 = sk256.verifying_key().to_encoded_point(false);
    assert!(compute_keyid("es256", pk256.as_bytes()).is_some());
    let raw_sig256: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk256, msg);
    let sig256 = raw_sig256.normalize_s().unwrap_or(raw_sig256);
    let sig256_bytes: [u8; 64] = sig256.to_bytes().into();
    assert!(verify_signature(
        "es256",
        pk256.as_bytes(),
        &sig256_bytes,
        msg
    ));
    let n256: [u8; 32] =
        decode_hex_arr("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut high_sig256 = sig256_bytes;
    let s256: [u8; 32] = sig256_bytes[32..64].try_into().unwrap();
    high_sig256[32..64].copy_from_slice(&sub_be(&n256, &s256));
    assert!(!verify_signature(
        "es256",
        pk256.as_bytes(),
        &high_sig256,
        msg
    ));

    let sk384 = p384::ecdsa::SigningKey::from_slice(&[10u8; 48]).unwrap();
    let pk384 = sk384.verifying_key().to_encoded_point(false);
    assert!(compute_keyid("es384", pk384.as_bytes()).is_some());
    let raw_sig384: p384::ecdsa::Signature = p384::ecdsa::signature::Signer::sign(&sk384, msg);
    let sig384 = raw_sig384.normalize_s().unwrap_or(raw_sig384);
    let sig384_bytes: [u8; 96] = sig384.to_bytes().as_slice().try_into().unwrap();
    assert!(verify_signature(
        "es384",
        pk384.as_bytes(),
        &sig384_bytes,
        msg
    ));
    let n384: [u8; 48] = decode_hex_arr(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    );
    let mut high_sig384 = sig384_bytes;
    let s384: [u8; 48] = sig384_bytes[48..96].try_into().unwrap();
    high_sig384[48..96].copy_from_slice(&sub_be(&n384, &s384));
    assert!(!verify_signature(
        "es384",
        pk384.as_bytes(),
        &high_sig384,
        msg
    ));
}

#[test]
fn definition_validator_key_bytes_derives_signers_and_all_rules() {
    let k1 = TestKey::from_seed(11);
    let k2 = TestKey::from_seed(12);
    let k3 = TestKey::from_seed(13);

    // Valid definition exercising keyBytes, derives, 3 signers, matchesSigner: 1, nested matchesSigner,
    // ordered (integers + cross-offset timestamps), exactlyOne, atMostOne, requires, values, nonEmpty, ref.anyOf
    let def_json = json!({
        "format": "r5e.kind-definition/v1",
        "kind": "custom.example.io/v1/Complex",
        "signatures": 3,
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["issuerField", "secondSigner", "thirdSigner", "pubKey", "derivedKid", "startTs", "endTs", "minSeq", "maxSeq", "choiceA", "mode", "extraMap", "anyRef"],
            "nonEmpty": ["extraMap"],
            "ordered": [["startTs", "endTs"], ["minSeq", "maxSeq"]],
            "exactlyOne": [["choiceA", "choiceB"]],
            "atMostOne": [["opt1", "opt2"]],
            "requires": [
                {"when": {"field": "mode", "equals": "strict"}, "then": ["strictNote"]}
            ],
            "properties": {
                "issuerField": {"type": "string", "matchesSigner": 1},
                "secondSigner": {"type": "string", "matchesSigner": 2},
                "thirdSigner": {"type": "string", "matchesSigner": 3},
                "nested": {
                    "type": "object",
                    "properties": {
                        "cosignerEcho": {"type": "string", "matchesSigner": 2}
                    }
                },
                "pubKey": {
                    "type": "object",
                    "keyBytes": true,
                    "required": ["algorithm", "bytes"],
                    "properties": {
                        "algorithm": {"type": "string"},
                        "bytes": {"type": "string"}
                    }
                },
                "derivedKid": {
                    "type": "string",
                    "derives": {"keyIdOf": "pubKey"}
                },
                "startTs": {
                    "type": "string",
                    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
                },
                "endTs": {
                    "type": "string",
                    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
                },
                "minSeq": {"type": "integer", "minimum": 1, "maximum": 100},
                "maxSeq": {"type": "integer", "minimum": 1, "maximum": 100},
                "choiceA": {"type": "boolean"},
                "choiceB": {"type": "boolean"},
                "opt1": {"type": "string"},
                "opt2": {"type": "string"},
                "mode": {"type": "string", "enum": ["normal", "strict"]},
                "strictNote": {"type": "string"},
                "extraMap": {
                    "type": "object",
                    "values": {"type": "integer", "minimum": 0}
                },
                "anyRef": {
                    "type": "ref",
                    "ref": {
                        "anyOf": [
                            {"bytes": true},
                            {"event": true}
                        ]
                    }
                }
            }
        }
    });
    let def_bytes = encode_canonical_json(&def_json).unwrap().into_bytes();
    let parsed = ParsedDefinition::parse(&def_bytes).expect("valid complex definition");

    let signers = vec![k1.keyid.clone(), k2.keyid.clone(), k3.keyid.clone()];
    let event_ref = format!("event:sha256:{}", "a".repeat(64));
    let valid_body = json!({
        "issuerField": k1.keyid,
        "secondSigner": k2.keyid,
        "thirdSigner": k3.keyid,
        "nested": {"cosignerEcho": k2.keyid},
        "pubKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(k1.pk)},
        "derivedKid": k1.keyid,
        "startTs": "2026-05-01T10:00:00+02:00", // 08:00:00Z
        "endTs": "2026-05-01T09:00:00Z",         // 09:00:00Z -> after startTs!
        "minSeq": 5,
        "maxSeq": 10,
        "choiceA": true,
        "opt1": "hello",
        "mode": "strict",
        "strictNote": "present",
        "extraMap": {"k": 42},
        "anyRef": event_ref,
    });
    assert!(parsed.validate_body(&valid_body, &signers));

    // Out-of-order timestamps across offsets (10:00:00+00:00 > 09:00:00Z) fails!
    let mut bad_order = valid_body.clone();
    bad_order["startTs"] = json!("2026-05-01T10:00:00+00:00");
    assert!(!parsed.validate_body(&bad_order, &signers));

    // Invalid calendar date (Feb 29 on non-leap year 2025) matching timestamp regex fails!
    let mut bad_cal = valid_body.clone();
    bad_cal["startTs"] = json!("2025-02-29T00:00:00Z");
    assert!(!parsed.validate_body(&bad_cal, &signers));

    // Wrong derived key id fails!
    let mut bad_derived = valid_body.clone();
    bad_derived["derivedKid"] = json!(k2.keyid);
    assert!(!parsed.validate_body(&bad_derived, &signers));

    // Non-strict base64 (`AB==`) or inadmissible key in `keyBytes` fails!
    let mut bad_kb = valid_body.clone();
    bad_kb["pubKey"]["bytes"] = json!("AB==");
    assert!(!parsed.validate_body(&bad_kb, &signers));

    // Empty `nonEmpty` map fails!
    let mut bad_empty = valid_body.clone();
    bad_empty["extraMap"] = json!({});
    assert!(!parsed.validate_body(&bad_empty, &signers));

    // Missing `requires.then` field fails!
    let mut bad_req = valid_body.clone();
    bad_req.as_object_mut().unwrap().remove("strictNote");
    assert!(!parsed.validate_body(&bad_req, &signers));

    // Both choices in `exactlyOne` fails!
    let mut bad_eo = valid_body.clone();
    bad_eo["choiceB"] = json!(false);
    assert!(!parsed.validate_body(&bad_eo, &signers));

    // Both options in `atMostOne` fails!
    let mut bad_amo = valid_body.clone();
    bad_amo["opt2"] = json!("world");
    assert!(!parsed.validate_body(&bad_amo, &signers));

    // Document-level faults must return `None` (`definition_not_available`):
    let bad_defs = [
        // `keyBytes` missing required `bytes`
        json!({
            "format": "r5e.kind-definition/v1",
            "kind": "x/v1/K",
            "schema": {
                "keyBytes": true,
                "required": ["algorithm"],
                "properties": {"algorithm": {"type": "string"}, "bytes": {"type": "string"}}
            }
        }),
        // `derives` referencing optional `keyBytes` property
        json!({
            "format": "r5e.kind-definition/v1",
            "kind": "x/v1/K",
            "schema": {
                "properties": {
                    "pk": {
                        "type": "object",
                        "keyBytes": true,
                        "required": ["algorithm", "bytes"],
                        "properties": {"algorithm": {"type": "string"}, "bytes": {"type": "string"}}
                    },
                    "kid": {"type": "string", "derives": {"keyIdOf": "pk"}}
                }
            }
        }),
        // `matchesSigner` above `signatures`
        json!({
            "format": "r5e.kind-definition/v1",
            "kind": "x/v1/K",
            "signatures": 1,
            "schema": {
                "required": ["s2"],
                "properties": {"s2": {"type": "string", "matchesSigner": 2}}
            }
        }),
        // Unknown schema keyword
        json!({
            "format": "r5e.kind-definition/v1",
            "kind": "x/v1/K",
            "schema": {"unknownKeyword": true}
        }),
        // Unspecified `ref` form (`crossChain`)
        json!({
            "format": "r5e.kind-definition/v1",
            "kind": "x/v1/K",
            "schema": {
                "properties": {"r": {"type": "ref", "ref": {"crossChain": true}}}
            }
        }),
    ];
    for bd in bad_defs {
        let bytes = encode_canonical_json(&bd).unwrap().into_bytes();
        assert!(
            ParsedDefinition::parse(&bytes).is_none(),
            "expected None for {bd}"
        );
    }
}

#[test]
fn unpinned_layer1_layer2_and_layer3_codes() {
    let issuer = TestKey::from_seed(21);
    let other = TestKey::from_seed(22);

    // Custom minimal carried definitions for SessionOpened and SessionClosed so §6.1 Step 3 passes
    // cleanly without inspecting base definition internals, exercising Step 4 (`session_differs_from_body`).
    let (session_opened_schema_ref, session_opened_def_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": "provenance.r5e.io/v2/SessionOpened",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["session"],
            "properties": {
                "session": {"type": "string"}
            }
        }
    }));
    let (session_closed_schema_ref, session_closed_def_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": "provenance.r5e.io/v2/SessionClosed",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["session"],
            "properties": {
                "session": {"type": "string"}
            }
        }
    }));
    let epoch_seal_schema_ref =
        "bytes:sha256:b0867d96e6bc35395dc0d78b8514cefe051d986a0f53f843d040918db4a5a5ad";

    let (prof_ref, prof_blob) = make_profile(
        json!({
            "provenance.r5e.io/v2/SessionOpened": session_opened_schema_ref,
            "provenance.r5e.io/v2/SessionClosed": session_closed_schema_ref,
            "provenance.r5e.io/v2/EpochSeal": epoch_seal_schema_ref,
        }),
        &[&issuer.keyid],
        &[&issuer.keyid],
    );

    // 1. `invalid_base64` on non-zero pad bits (`AB==`) in record payload, blob, and key,
    //    plus `conflicting_or_unreadable_key`, `payload_not_an_object`, and `issuer_is_not_signer`.
    let arr_payload = b"[1,2,3]";
    let arr_ref = evidence_ref_of(arr_payload);
    let wrong_issuer_payload = encode_canonical_json(&json!({"issuer": other.keyid}))
        .unwrap()
        .into_bytes();
    let wrong_issuer_ref = evidence_ref_of(&wrong_issuer_payload);
    let bad_b64_ref = format!("evidence:sha256:{}", "1".repeat(64));
    let bad_blob_ref = format!("bytes:sha256:{}", "2".repeat(64));

    let b1 = empty_bundle_with(
        vec![
            json!({
                "ref": bad_b64_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE_V2,
                    "payload": "AB==",
                    "signatures": [{"keyid": issuer.keyid, "sig": STANDARD.encode([0u8; 64])}]
                }
            }),
            json!({
                "ref": arr_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE_V2,
                    "payload": STANDARD.encode(arr_payload),
                    "signatures": [issuer.sign_payload(arr_payload)]
                }
            }),
            json!({
                "ref": wrong_issuer_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE_V2,
                    "payload": STANDARD.encode(&wrong_issuer_payload),
                    "signatures": [issuer.sign_payload(&wrong_issuer_payload)]
                }
            }),
        ],
        vec![json!({"ref": bad_blob_ref, "base64": "AB=="})],
        vec![
            issuer.key_json(),
            // Conflicting bytes for the same keyid
            json!({
                "keyid": issuer.keyid,
                "algorithm": "ed25519",
                "bytes": STANDARD.encode(other.pk),
            }),
        ],
        vec![],
        vec![],
    );
    let r1 = verify_bundle_value(&b1, &VerifyOptions::default());
    let codes1: Vec<&str> = r1.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes1.contains(&"invalid_base64"));
    assert!(codes1.contains(&"conflicting_or_unreadable_key"));
    assert!(codes1.contains(&"payload_not_an_object"));
    assert!(codes1.contains(&"issuer_is_not_signer"));

    // 2. `causes_not_sorted_and_unique`, `session_differs_from_body` (both SessionOpened mismatch
    //    and SessionClosed missing envelope `session`), `profile_not_available`, `unreadable_profile`
    let cause_a = format!("evidence:sha256:{}", "a".repeat(64));
    let cause_b = format!("evidence:sha256:{}", "b".repeat(64));
    let unsorted_causes_payload = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "SessionOpened",
        "schemaRef": session_opened_schema_ref,
        "profileRef": prof_ref,
        "issuer": issuer.keyid,
        "actor": "actor:agent",
        "stream": "stream:s1",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-10T00:00:00Z",
        "causes": [cause_b, cause_a],
        "session": "session:one",
        "body": {
            "session": "session:one"
        }
    });
    let (_, rec_unsorted) = make_signed_record(&unsorted_causes_payload, &[&issuer]);

    let missing_prof_ref = format!("bytes:sha256:{}", "9".repeat(64));
    let bad_prof_bytes = b"{\"not\":\"a valid profile\"}";
    let bad_prof_ref = bytes_ref_of(bad_prof_bytes);

    let session_mismatch_payload = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "SessionOpened",
        "schemaRef": session_opened_schema_ref,
        "profileRef": missing_prof_ref,
        "issuer": issuer.keyid,
        "actor": "actor:agent",
        "stream": "stream:s2",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-10T00:00:00Z",
        "session": "session:envelope",
        "body": {
            "session": "session:body-different"
        }
    });
    let (sess_mismatch_ref, rec_sess_mismatch) =
        make_signed_record(&session_mismatch_payload, &[&issuer]);

    // SessionClosed with both envelope `session` and body `session` present and unequal -> `session_differs_from_body`!
    let unreadable_prof_payload = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "SessionClosed",
        "schemaRef": session_closed_schema_ref,
        "profileRef": bad_prof_ref,
        "issuer": issuer.keyid,
        "actor": "actor:agent",
        "stream": "stream:s3",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-10T00:00:00Z",
        "session": "session:envelope-closed",
        "body": {
            "session": "session:three"
        }
    });
    let (sess_closed_ref, rec_unreadable_prof) =
        make_signed_record(&unreadable_prof_payload, &[&issuer]);

    // 3. Layer 3 unpinned seal & proof codes: `seal_record_not_carried`, `not_an_epoch_seal`,
    //    `unreadable_manifest`, `not_every_covered_record_is_carried`, `seal_or_record_not_carried`
    let bad_manifest_bytes = b"{\"format\":\"r5e.provenance-epoch/v2\",\"events\":[]}";
    let bad_manifest_ref = bytes_ref_of(bad_manifest_bytes);
    let seal_unreadable_manifest_payload = json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "EpochSeal",
        "schemaRef": epoch_seal_schema_ref,
        "profileRef": prof_ref,
        "issuer": issuer.keyid,
        "actor": "actor:sealer",
        "stream": "stream:seals",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-10T00:00:00Z",
        "body": {
            "stream": "stream:s1",
            "firstSeq": 1,
            "lastSeq": 1,
            "root": format!("sha256:{}", "0".repeat(64)),
            "manifestRef": bad_manifest_ref
        }
    });
    let (seal_bad_man_ref, rec_seal_bad_man) =
        make_signed_record(&seal_unreadable_manifest_payload, &[&issuer]);

    let missing_ev_ref = format!("evidence:sha256:{}", "7".repeat(64));
    let (uncarried_man_ref, uncarried_man_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [missing_ev_ref]
    }));
    let (seal_uncarried_ev_ref, rec_seal_uncarried_ev) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": epoch_seal_schema_ref,
            "profileRef": prof_ref,
            "issuer": issuer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seals-uncarried",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "stream": "stream:s1",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": format!("sha256:{}", "0".repeat(64)),
                "manifestRef": uncarried_man_ref
            }
        }),
        &[&issuer],
    );

    let missing_seal_ref = format!("evidence:sha256:{}", "e".repeat(64));

    let b2 = empty_bundle_with(
        vec![
            rec_unsorted,
            rec_sess_mismatch,
            rec_unreadable_prof,
            rec_seal_bad_man,
            rec_seal_uncarried_ev,
        ],
        vec![
            session_opened_def_blob,
            session_closed_def_blob,
            prof_blob,
            json!({"ref": bad_prof_ref, "base64": STANDARD.encode(bad_prof_bytes)}),
            json!({"ref": bad_manifest_ref, "base64": STANDARD.encode(bad_manifest_bytes)}),
            uncarried_man_blob,
        ],
        vec![issuer.key_json()],
        vec![
            json!(missing_seal_ref),
            json!(sess_mismatch_ref), // not an EpochSeal!
            json!(seal_bad_man_ref),
            json!(seal_uncarried_ev_ref),
        ],
        vec![json!({
            "record": sess_mismatch_ref,
            "seal": missing_seal_ref,
            "index": 0,
            "siblings": []
        })],
    );
    let r2 = verify_bundle_value(&b2, &VerifyOptions::default());
    let codes2: Vec<&str> = r2.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes2.contains(&"causes_not_sorted_and_unique"));
    assert!(codes2.contains(&"session_differs_from_body"));
    assert!(r2.findings.iter().any(|f| f.subject == sess_closed_ref
        && f.check == "body"
        && f.code == "session_differs_from_body"));
    assert!(codes2.contains(&"profile_not_available"));
    assert!(codes2.contains(&"unreadable_profile"));
    assert!(codes2.contains(&"seal_record_not_carried"));
    assert!(codes2.contains(&"not_an_epoch_seal"));
    assert!(codes2.contains(&"unreadable_manifest"));
    assert!(codes2.contains(&"not_every_covered_record_is_carried"));
    assert!(codes2.contains(&"seal_or_record_not_carried"));
}

#[test]
fn merkle_uneven_inclusion_proofs_and_epoch_codes() {
    // 3-leaf tree RFC 9162 inclusion proof verification (exact sibling counts & wrong sibling rejection)
    let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let root = merkle_root(&leaves);
    let l0 = merkle_leaf_hash(&leaves[0]);
    let l1 = merkle_leaf_hash(&leaves[1]);
    let l2 = merkle_leaf_hash(&leaves[2]);
    let n01 = merkle_node_hash(&l0, &l1);

    assert!(verify_inclusion_proof(&leaves[0], 0, 3, &[l1, l2], &root));
    assert!(verify_inclusion_proof(&leaves[1], 1, 3, &[l0, l2], &root));
    assert!(verify_inclusion_proof(&leaves[2], 2, 3, &[n01], &root));
    // Extra unused sibling must fail ("must use every sibling")
    assert!(!verify_inclusion_proof(
        &leaves[2],
        2,
        3,
        &[n01, [9u8; 32]],
        &root
    ));
    // Missing sibling must fail
    assert!(!verify_inclusion_proof(&leaves[0], 0, 3, &[l1], &root));

    // Also test epoch_range_length, epoch_stream, epoch_sequence, epoch_previous, and proof_does_not_reach_root
    let issuer = TestKey::from_seed(31);
    let obs_schema_ref =
        "bytes:sha256:6f157d4f46bd1da4dc566c4f64d7d0aa99d4bffc16c140ed063051676cf0c0cf";
    let seal_schema_ref =
        "bytes:sha256:b0867d96e6bc35395dc0d78b8514cefe051d986a0f53f843d040918db4a5a5ad";
    let (prof_ref, prof_blob) = make_profile(
        json!({
            "provenance.r5e.io/v2/Observation": obs_schema_ref,
            "provenance.r5e.io/v2/EpochSeal": seal_schema_ref,
        }),
        &[&issuer.keyid],
        &[&issuer.keyid],
    );
    let (content_ref, content_blob) = make_blob(&json!({"hello": "world"}));

    let make_obs = |stream: &str, seq: i64, previous: Value| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_schema_ref,
                "profileRef": prof_ref,
                "issuer": issuer.keyid,
                "actor": "actor:a",
                "stream": stream,
                "seq": seq,
                "previous": previous,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "source": "sensor",
                    "contentRef": content_ref,
                    "mediaType": "application/json",
                    "size": 999999 // §11: size is intentionally not compared with content length
                }
            }),
            &[&issuer],
        )
    };
    let digest_of = |ev_ref: &str| -> [u8; 32] {
        r5e_verify_rs::provenance_v2::canonical::decode_hex_32(
            ev_ref.strip_prefix("evidence:sha256:").unwrap(),
        )
        .unwrap()
    };

    let (ev1_ref, ev1_rec) = make_obs("stream:target", 1, Value::Null);
    let true_root_1 = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&ev1_ref)]))
    );
    let (man1_ref, man1_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [ev1_ref],
    }));

    // 1. Seal with lastSeq=2 vs 1 event -> `epoch_range_length`, plus proof on 2-leaf tree with empty siblings -> `proof_does_not_reach_root`
    let (seal_range_ref, seal_range_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_schema_ref,
            "profileRef": prof_ref,
            "issuer": issuer.keyid,
            "actor": "actor:a",
            "stream": "stream:seals-1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "stream": "stream:target",
                "firstSeq": 1,
                "lastSeq": 2,
                "root": true_root_1,
                "manifestRef": man1_ref
            }
        }),
        &[&issuer],
    );

    // 2. Seal over a record from a different stream -> `epoch_stream`
    let (seal_stream_ref, seal_stream_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_schema_ref,
            "profileRef": prof_ref,
            "issuer": issuer.keyid,
            "actor": "actor:a",
            "stream": "stream:seals-2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "stream": "stream:other-stream",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": true_root_1,
                "manifestRef": man1_ref
            }
        }),
        &[&issuer],
    );

    // 3. Seal with firstSeq=2, lastSeq=2 over ev1 (which has seq=1) -> `epoch_sequence`
    let (seal_seq_ref, seal_seq_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_schema_ref,
            "profileRef": prof_ref,
            "issuer": issuer.keyid,
            "actor": "actor:a",
            "stream": "stream:seals-3",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "stream": "stream:target",
                "firstSeq": 2,
                "lastSeq": 2,
                "root": true_root_1,
                "manifestRef": man1_ref,
                "previousSeal": format!("evidence:sha256:{}", "8".repeat(64))
            }
        }),
        &[&issuer],
    );

    // 4. Seal with firstSeq=1, lastSeq=2 where record 2 points to wrong `previous` -> `epoch_previous`
    let wrong_prev = format!("evidence:sha256:{}", "6".repeat(64));
    let (ev2_bad_prev_ref, ev2_bad_prev_rec) = make_obs("stream:target", 2, json!(wrong_prev));
    let root_12 = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[
            digest_of(&ev1_ref),
            digest_of(&ev2_bad_prev_ref)
        ]))
    );
    let (man12_ref, man12_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [ev1_ref, ev2_bad_prev_ref],
    }));
    let (seal_prev_ref, seal_prev_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_schema_ref,
            "profileRef": prof_ref,
            "issuer": issuer.keyid,
            "actor": "actor:a",
            "stream": "stream:seals-4",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "stream": "stream:target",
                "firstSeq": 1,
                "lastSeq": 2,
                "root": root_12,
                "manifestRef": man12_ref
            }
        }),
        &[&issuer],
    );

    let bundle = empty_bundle_with(
        vec![
            ev1_rec,
            ev2_bad_prev_rec,
            seal_range_rec,
            seal_stream_rec,
            seal_seq_rec,
            seal_prev_rec,
        ],
        vec![prof_blob, content_blob, man1_blob, man12_blob],
        vec![issuer.key_json()],
        vec![
            json!(seal_range_ref),
            json!(seal_stream_ref),
            json!(seal_seq_ref),
            json!(seal_prev_ref),
        ],
        vec![json!({
            "record": ev1_ref,
            "seal": seal_range_ref,
            "index": 0,
            "siblings": []
        })],
    );
    let rep = verify_bundle_value(&bundle, &VerifyOptions::default());
    let codes: Vec<&str> = rep.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes.contains(&"epoch_range_length"));
    assert!(codes.contains(&"epoch_stream"));
    assert!(codes.contains(&"epoch_sequence"));
    assert!(codes.contains(&"epoch_previous"));
    assert!(codes.contains(&"proof_does_not_reach_root"));
}

#[test]
fn cli_exit_codes_0_1_2_3_allow_incomplete_and_definitions_dir() {
    let bin = env!("CARGO_BIN_EXE_recurse_verify");
    let cases = vectors_cases_dir();

    // 1. Exit 0: `valid-single-record-ed25519` with its trusted profile and publisher
    let c0_dir = cases.join("valid-single-record-ed25519");
    let c0_meta: Value =
        serde_json::from_slice(&fs::read(c0_dir.join("case.json")).unwrap()).unwrap();
    let mut cmd0 = Command::new(bin);
    cmd0.arg(c0_dir.join("bundle.json"));
    for tp in c0_meta["trustedProfiles"].as_array().unwrap() {
        cmd0.arg("--trusted-profile").arg(tp.as_str().unwrap());
    }
    for pub_k in c0_meta["trustedPublishers"].as_array().unwrap() {
        cmd0.arg("--trusted-publisher").arg(pub_k.as_str().unwrap());
    }
    let out0 = cmd0.output().unwrap();
    assert_eq!(out0.status.code(), Some(0));
    let out0_str = std::str::from_utf8(&out0.stdout)
        .unwrap()
        .trim_end_matches('\n');
    // Output must be canonical JSON
    assert!(parse_canonical_json(out0_str.as_bytes()).is_some());

    // 2. Exit 3 without `--allow-incomplete`, and Exit 0 WITH `--allow-incomplete`
    let c3_bundle = cases.join("untrusted-profile").join("bundle.json");
    let out3 = Command::new(bin).arg(&c3_bundle).output().unwrap();
    assert_eq!(out3.status.code(), Some(3));

    let out3_allowed = Command::new(bin)
        .arg("provenance")
        .arg(&c3_bundle)
        .arg("--allow-incomplete")
        .output()
        .unwrap();
    assert_eq!(out3_allowed.status.code(), Some(0));

    // 3. Exit 1 when any check fails
    let c1_bundle = cases.join("bad-signature").join("bundle.json");
    let out1 = Command::new(bin).arg(&c1_bundle).output().unwrap();
    assert_eq!(out1.status.code(), Some(1));

    // 4. Exit 2 on unreadable input or invalid JSON
    let tmp = TempDir::new();
    let missing = tmp.0.join("does-not-exist.json");
    let out2_missing = Command::new(bin)
        .arg("provenance")
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out2_missing.status.code(), Some(2));
    assert!(out2_missing.stdout.is_empty());

    let bad_json = tmp.0.join("bad.json");
    fs::write(&bad_json, b"{\"dup\":1,\"dup\":2}").unwrap();
    let out2_dup = Command::new(bin).arg(&bad_json).output().unwrap();
    assert_eq!(out2_dup.status.code(), Some(2));
    assert!(out2_dup.stdout.is_empty());

    // 5. `--definitions-dir` loads extra installed definition by hash
    let ext_with_def_bundle: Value = serde_json::from_slice(
        &fs::read(cases.join("extension-kind-with-definition/bundle.json")).unwrap(),
    )
    .unwrap();
    let ext_without_bundle_path = cases.join("extension-kind-without-definition/bundle.json");
    let ext_meta: Value = serde_json::from_slice(
        &fs::read(cases.join("extension-kind-without-definition/case.json")).unwrap(),
    )
    .unwrap();
    let defs_dir = tmp.0.join("installed-defs");
    fs::create_dir_all(&defs_dir).unwrap();
    for (idx, blob) in ext_with_def_bundle["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let raw = STANDARD.decode(blob["base64"].as_str().unwrap()).unwrap();
        fs::write(defs_dir.join(format!("blob-{idx}.json")), raw).unwrap();
    }
    let mut cmd_ext = Command::new(bin);
    cmd_ext
        .arg(&ext_without_bundle_path)
        .arg("--definitions-dir")
        .arg(&defs_dir);
    for tp in ext_meta["trustedProfiles"].as_array().unwrap() {
        cmd_ext.arg("--trusted-profile").arg(tp.as_str().unwrap());
    }
    for pub_k in ext_meta["trustedPublishers"].as_array().unwrap() {
        cmd_ext
            .arg("--trusted-publisher")
            .arg(pub_k.as_str().unwrap());
    }
    let out_ext = cmd_ext.output().unwrap();
    let rep_ext: Value = serde_json::from_slice(&out_ext.stdout).unwrap();
    // Every `body` finding in `extension-kind-without-definition` now resolves to `ok`!
    for f in rep_ext["findings"].as_array().unwrap() {
        if f["check"] == "body" {
            assert_eq!(
                f["result"], "ok",
                "expected body ok with installed definition: {f}"
            );
        }
    }
}

#[test]
fn publications_multiple_versions_failed_publisher_sig_and_second_seal() {
    let publisher = TestKey::from_seed(41);
    let issuer = TestKey::from_seed(42);

    let def_pub_schema_ref =
        "bytes:sha256:a29219a754d9733dd402c8a58eea0dfa8c85a2ce588065e19a29e5459e760ccc";
    let seal_schema_ref =
        "bytes:sha256:b0867d96e6bc35395dc0d78b8514cefe051d986a0f53f843d040918db4a5a5ad";

    // Two distinct valid definitions for `custom.example.io/v1/Note`
    let (def1_ref, def1_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": "custom.example.io/v1/Note",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["v1"],
            "properties": {"v1": {"type": "string"}}
        }
    }));
    let (def2_ref, def2_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": "custom.example.io/v1/Note",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["v2"],
            "properties": {"v2": {"type": "string"}}
        }
    }));

    let (prof1_ref, prof1_blob) = make_profile(
        json!({
            "provenance.r5e.io/v2/DefinitionPublished": def_pub_schema_ref,
            "provenance.r5e.io/v2/EpochSeal": seal_schema_ref,
            "custom.example.io/v1/Note": def1_ref,
        }),
        &[&publisher.keyid, &issuer.keyid],
        &[&issuer.keyid],
    );
    let (prof2_ref, prof2_blob) = make_profile(
        json!({
            "custom.example.io/v1/Note": def2_ref,
        }),
        &[&issuer.keyid],
        &[&issuer.keyid],
    );

    let (_, pub1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_schema_ref,
            "profileRef": prof1_ref,
            "issuer": publisher.keyid,
            "actor": "actor:pub",
            "stream": "stream:pubs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": def_pub_schema_ref},
                    {"kind": "provenance.r5e.io/v2/EpochSeal", "definition": seal_schema_ref},
                    {"kind": "custom.example.io/v1/Note", "definition": def1_ref}
                ]
            }
        }),
        &[&publisher],
    );
    let (pub1_ref_val, _) = (pub1_rec["ref"].as_str().unwrap().to_string(), ());
    let (_, pub2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_schema_ref,
            "profileRef": prof1_ref,
            "issuer": publisher.keyid,
            "actor": "actor:pub",
            "stream": "stream:pubs",
            "seq": 2,
            "previous": pub1_ref_val,
            "capturedAt": "2026-11-10T00:00:01Z",
            "body": {
                "definitions": [
                    {"kind": "custom.example.io/v1/Note", "definition": def2_ref}
                ]
            }
        }),
        &[&publisher],
    );

    // Also include a forged publication whose signature is bad — it must state nothing!
    let forged_def_ref = format!("bytes:sha256:{}", "f".repeat(64));
    let forged_payload = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "DefinitionPublished",
        "schemaRef": def_pub_schema_ref,
        "profileRef": prof1_ref,
        "issuer": publisher.keyid,
        "actor": "actor:pub",
        "stream": "stream:forged",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-10T00:00:02Z",
        "body": {
            "definitions": [
                {"kind": "custom.example.io/v1/Unpublished", "definition": forged_def_ref}
            ]
        }
    }))
    .unwrap()
    .into_bytes();
    let forged_rec = json!({
        "ref": evidence_ref_of(&forged_payload),
        "envelope": {
            "payloadType": DSSE_PAYLOAD_TYPE_V2,
            "payload": STANDARD.encode(&forged_payload),
            "signatures": [{"keyid": publisher.keyid, "sig": STANDARD.encode([0u8; 64])}]
        }
    });

    // Note record 1 (seq 1, omitted from bundle) and Note record 2 (seq 2, using def2, sealed by second seal with firstSeq=2 and previousSeal!)
    let dummy_ev1_ref = format!("evidence:sha256:{}", "c".repeat(64));
    let dummy_seal1_ref = format!("evidence:sha256:{}", "d".repeat(64));
    let (_, note1_rec) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "Note",
            "schemaRef": def1_ref,
            "profileRef": prof1_ref,
            "issuer": issuer.keyid,
            "actor": "actor:writer",
            "stream": "stream:notes-a",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T00:00:03Z",
            "body": {"v1": "hello"}
        }),
        &[&issuer],
    );
    let (note2_ref, note2_rec) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "Note",
            "schemaRef": def2_ref,
            "profileRef": prof2_ref,
            "issuer": issuer.keyid,
            "actor": "actor:writer",
            "stream": "stream:notes-b",
            "seq": 2,
            "previous": dummy_ev1_ref,
            "capturedAt": "2026-11-10T00:00:04Z",
            "body": {"v2": "world"}
        }),
        &[&issuer],
    );

    let note2_digest = r5e_verify_rs::provenance_v2::canonical::decode_hex_32(
        note2_ref.strip_prefix("evidence:sha256:").unwrap(),
    )
    .unwrap();
    let epoch2_root = format!("sha256:{}", hex_encode(&merkle_root(&[note2_digest])));
    let (man2_ref, man2_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [note2_ref],
    }));
    let (seal2_ref, seal2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_schema_ref,
            "profileRef": prof1_ref,
            "issuer": issuer.keyid,
            "actor": "actor:writer",
            "stream": "stream:seals",
            "seq": 2,
            "previous": dummy_seal1_ref,
            "capturedAt": "2026-11-10T00:00:05Z",
            "body": {
                "stream": "stream:notes-b",
                "firstSeq": 2,
                "lastSeq": 2,
                "root": epoch2_root,
                "manifestRef": man2_ref,
                "previousSeal": dummy_seal1_ref
            }
        }),
        &[&issuer],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_profiles.insert(prof1_ref);
    opts.trusted_profiles.insert(prof2_ref);
    opts.trusted_publishers.insert(publisher.keyid.clone());

    let bundle = empty_bundle_with(
        vec![
            pub1_rec,
            pub2_rec,
            forged_rec,
            note1_rec.clone(),
            note2_rec,
            seal2_rec,
        ],
        vec![def1_blob, def2_blob, prof1_blob, prof2_blob, man2_blob],
        vec![publisher.key_json(), issuer.key_json()],
        vec![json!(seal2_ref)],
        vec![],
    );
    let rep = verify_bundle_value(&bundle, &opts);

    // Both Note records (def1 and def2) have `publication: ok`, and the second seal (`firstSeq: 2`) has `epoch: ok` (`seq:2-2`)!
    let note1_ref_str = note1_rec["ref"].as_str().unwrap();
    assert!(
        rep.findings
            .iter()
            .any(|f| f.subject == note1_ref_str && f.check == "publication" && f.result == "ok")
    );
    assert!(
        rep.findings
            .iter()
            .any(|f| f.subject == note2_ref && f.check == "publication" && f.result == "ok")
    );
    assert!(rep.findings.iter().any(|f| f.subject == seal2_ref
        && f.check == "epoch"
        && f.result == "ok"
        && f.about.as_deref() == Some("seq:2-2")));
}

fn base_schema_ref(kind_path: &str) -> String {
    let idx: Value = serde_json::from_slice(include_bytes!(
        "../vendor/provenance-v2/definitions/index.json"
    ))
    .unwrap();
    idx[kind_path].as_str().unwrap().to_string()
}

fn find_authority_finding<'a>(
    rep: &'a r5e_verify_rs::provenance_v2::Report,
    subject: &str,
) -> Option<&'a r5e_verify_rs::provenance_v2::Finding> {
    rep.findings
        .iter()
        .find(|f| f.layer == 2 && f.subject == subject && f.check == "authority")
}

#[test]
fn a5_link_narrowing_may_endorse_self_endorsement_and_16_link_cap() {
    let root = TestKey::from_seed(50);
    let gw = TestKey::from_seed(51);
    let worker = TestKey::from_seed(52);
    let stranger = TestKey::from_seed(53);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");
    let princ_sref = base_schema_ref("provenance.r5e.io/v2/Principal");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"absent-profile");

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    // 1. Principal record gets NO authority finding under A5, and absent profileRef still emits A5 authority on others.
    let (princ_ref, princ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Principal",
            "schemaRef": princ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:id-0",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "key": root.keyid,
                "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root.pk)},
                "holder": "org"
            }
        }),
        &[&root],
    );

    // 2. Self-endorsements: root -> root (parentless), stranger -> stranger (parentless), and gw -> gw (with parent)
    let (self_root_ref, self_root_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:self-root",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": root.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root],
    );
    let (root_obs_ref, root_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:01:00Z",
            "body": {"topic": "root-direct", "contentRefs": []}
        }),
        &[&root],
    );
    let (self_stranger_ref, self_stranger_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "stream:self-stranger",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": stranger.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&stranger],
    );
    let (stranger_obs_ref, stranger_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "stream:stranger-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:01:00Z",
            "body": {"topic": "stranger", "contentRefs": []}
        }),
        &[&stranger],
    );

    // Valid constrained parent L0: root -> gw
    let (l0_ref, l0_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:l0",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T12:00:00Z",
                "streamPrefixes": ["stream:app/"],
                "actorPrefixes": ["actor:svc/"],
                "actsFor": "user:alice"
            }
        }),
        &[&root],
    );

    // Non-endorsing grant L0_no_endorse: root -> gw with mayEndorse: false
    let (l0_no_end_ref, l0_no_end_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:l0-ne",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T12:00:00Z"
            }
        }),
        &[&root],
    );

    let mk_child_badge = |stream_id: &str, captured_at: &str, body_override: Value| {
        let mut body = json!({
            "subject": worker.keyid,
            "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(worker.pk)},
            "holder": "worker",
            "kinds": ["provenance.r5e.io/v2/Observation"],
            "notBefore": "2026-11-10T10:05:00Z",
            "notAfter": "2026-11-10T11:55:00Z",
            "parent": l0_ref,
            "streamPrefixes": ["stream:app/sub/"],
            "actorPrefixes": ["actor:svc/worker"],
            "actsFor": "user:alice"
        });
        for (k, v) in body_override.as_object().unwrap() {
            if v.is_null() {
                body.as_object_mut().unwrap().remove(k);
            } else {
                body[k] = v.clone();
            }
        }
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Badge",
                "schemaRef": badge_sref,
                "profileRef": dummy_prof_ref,
                "issuer": gw.keyid,
                "actor": "actor:gw",
                "stream": stream_id,
                "seq": 1,
                "previous": null,
                "capturedAt": captured_at,
                "body": body
            }),
            &[&gw, &worker],
        )
    };

    // Valid narrowed badge
    let (b_ok_ref, b_ok_rec) = mk_child_badge("stream:b-ok", "2026-11-10T10:05:00Z", json!({}));
    // Badge under non-endorsing parent (`mayEndorse: false`)
    let (b_ne_ref, b_ne_rec) = mk_child_badge(
        "stream:b-ne",
        "2026-11-10T10:05:00Z",
        json!({"parent": l0_no_end_ref, "streamPrefixes": null, "actorPrefixes": null, "actsFor": null}),
    );
    // Child naming extra kind
    let (b_kind_ref, b_kind_rec) = mk_child_badge(
        "stream:b-kind",
        "2026-11-10T10:05:00Z",
        json!({"kinds": ["provenance.r5e.io/v2/Observation", "provenance.r5e.io/v2/ToolCall"]}),
    );
    // Child with wider window (12:30+02:00 == 10:30Z is fine, 11:30+02:00 == 09:30Z < 10:00Z fails!)
    let (b_win_ref, b_win_rec) = mk_child_badge(
        "stream:b-win",
        "2026-11-10T10:05:00Z",
        json!({"notBefore": "2026-11-10T11:30:00+02:00"}),
    );
    // Child issued outside parent's window (§4.6: capturedAt > parent.notAfter)
    let (b_late_issue_ref, b_late_issue_rec) =
        mk_child_badge("stream:b-late", "2026-11-10T12:00:01Z", json!({}));
    // Child dropping actsFor
    let (b_no_af_ref, b_no_af_rec) = mk_child_badge(
        "stream:b-noaf",
        "2026-11-10T10:05:00Z",
        json!({"actsFor": null}),
    );
    // Child changing actsFor
    let (b_diff_af_ref, b_diff_af_rec) = mk_child_badge(
        "stream:b-diffaf",
        "2026-11-10T10:05:00Z",
        json!({"actsFor": "user:bob"}),
    );
    // Child dropping streamPrefixes
    let (b_no_sp_ref, b_no_sp_rec) = mk_child_badge(
        "stream:b-nosp",
        "2026-11-10T10:05:00Z",
        json!({"streamPrefixes": null}),
    );
    // Child widening streamPrefixes
    let (b_wide_sp_ref, b_wide_sp_rec) = mk_child_badge(
        "stream:b-widesp",
        "2026-11-10T10:05:00Z",
        json!({"streamPrefixes": ["stream:other/"]}),
    );
    // Child dropping actorPrefixes
    let (b_no_ap_ref, b_no_ap_rec) = mk_child_badge(
        "stream:b-noap",
        "2026-11-10T10:05:00Z",
        json!({"actorPrefixes": null}),
    );
    // Child widening actorPrefixes
    let (b_wide_ap_ref, b_wide_ap_rec) = mk_child_badge(
        "stream:b-wideap",
        "2026-11-10T10:05:00Z",
        json!({"actorPrefixes": ["actor:other/"]}),
    );
    // Self-endorsement with parent (gw -> gw)
    let (self_gw_ref, self_gw_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:self-gw",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:05:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:05:00Z",
                "notAfter": "2026-11-10T11:55:00Z",
                "parent": l0_ref,
                "streamPrefixes": ["stream:app/"],
                "actorPrefixes": ["actor:svc/"],
                "actsFor": "user:alice"
            }
        }),
        &[&gw],
    );

    // Missing parent when carried links already fail (`mayEndorse: false` carried middle link whose own parent is missing!)
    let missing_top_ref = format!("evidence:sha256:{}", "a".repeat(64));
    let (mid_bad_ref, mid_bad_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:mid-bad",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T12:00:00Z",
                "parent": missing_top_ref
            }
        }),
        &[&root],
    );
    let (b_under_mid_bad_ref, b_under_mid_bad_rec) = mk_child_badge(
        "stream:b-mid-bad",
        "2026-11-10T10:05:00Z",
        json!({"parent": mid_bad_ref, "streamPrefixes": null, "actorPrefixes": null, "actsFor": null}),
    );
    // Carried parent that is an Observation (not a grant) -> must fail `not_covered`, NOT `chain_not_carried`!
    let (b_obs_parent_ref, b_obs_parent_rec) = mk_child_badge(
        "stream:b-obs-parent",
        "2026-11-10T10:05:00Z",
        json!({"parent": root_obs_ref}),
    );

    let bundle = empty_bundle_with(
        vec![
            princ_rec,
            self_root_rec,
            root_obs_rec,
            self_stranger_rec,
            stranger_obs_rec,
            l0_rec,
            l0_no_end_rec,
            b_ok_rec,
            b_ne_rec,
            b_kind_rec,
            b_win_rec,
            b_late_issue_rec,
            b_no_af_rec,
            b_diff_af_rec,
            b_no_sp_rec,
            b_wide_sp_rec,
            b_no_ap_rec,
            b_wide_ap_rec,
            self_gw_rec,
            mid_bad_rec,
            b_under_mid_bad_rec,
            b_obs_parent_rec,
        ],
        vec![],
        vec![
            root.key_json(),
            gw.key_json(),
            worker.key_json(),
            stranger.key_json(),
        ],
        vec![],
        vec![],
    );

    let rep = verify_bundle_value(&bundle, &opts);

    assert!(find_authority_finding(&rep, &princ_ref).is_none());
    assert_eq!(
        find_authority_finding(&rep, &self_root_ref).unwrap().code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &root_obs_ref).unwrap().code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &self_stranger_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &stranger_obs_ref)
            .unwrap()
            .code,
        "no_standing"
    );
    assert_eq!(find_authority_finding(&rep, &b_ok_ref).unwrap().code, "ok");
    assert_eq!(
        find_authority_finding(&rep, &b_ok_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(l0_ref.as_str())
    );

    for bad_ref in [
        &b_ne_ref,
        &b_kind_ref,
        &b_win_ref,
        &b_late_issue_ref,
        &b_no_af_ref,
        &b_diff_af_ref,
        &b_no_sp_ref,
        &b_wide_sp_ref,
        &b_no_ap_ref,
        &b_wide_ap_ref,
        &self_gw_ref,
        &b_under_mid_bad_ref,
        &b_obs_parent_ref,
    ] {
        let f = find_authority_finding(&rep, bad_ref).unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..]),
            ("failed", "not_covered"),
            "expected failed/not_covered for {bad_ref}, got {f:?}"
        );
    }

    // 3. Test 16-link chain cap: 16 links succeeds, 17 links fails `not_covered`!
    let chain_keys: Vec<TestKey> = (60..=77).map(TestKey::from_seed).collect();
    let mut chain_recs = Vec::new();
    let mut prev_link_ref: Option<String> = None;
    let mut link16_subj_idx = 0usize;
    for step in 0..17 {
        let iss = &chain_keys[step];
        let sub = &chain_keys[step + 1];
        let mut body = json!({
            "subject": sub.keyid,
            "kinds": ["provenance.r5e.io/v2/Observation"],
            "mayEndorse": true,
            "notBefore": "2026-11-10T10:00:00Z",
            "notAfter": "2026-11-10T12:00:00Z"
        });
        if let Some(pref) = &prev_link_ref {
            body["parent"] = json!(pref);
        }
        let (lref, lrec) = make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Endorsement",
                "schemaRef": end_sref,
                "profileRef": dummy_prof_ref,
                "issuer": iss.keyid,
                "actor": "actor:chain",
                "stream": format!("stream:chain-{step}"),
                "seq": 1,
                "previous": null,
                "capturedAt": "2026-11-10T10:01:00Z",
                "body": body
            }),
            &[iss],
        );
        if step == 15 {
            link16_subj_idx = step + 1;
        }
        prev_link_ref = Some(lref);
        chain_recs.push(lrec);
    }
    let link16_ref = chain_recs[15]["ref"].as_str().unwrap().to_string();
    let link17_ref = chain_recs[16]["ref"].as_str().unwrap().to_string();

    let (obs16_ref, obs16_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": chain_keys[link16_subj_idx].keyid,
            "actor": "actor:chain",
            "stream": "stream:obs-16",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:02:00Z",
            "body": {"topic": "depth16", "contentRefs": []}
        }),
        &[&chain_keys[link16_subj_idx]],
    );
    let (obs17_ref, obs17_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": chain_keys[17].keyid,
            "actor": "actor:chain",
            "stream": "stream:obs-17",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:02:00Z",
            "body": {"topic": "depth17", "contentRefs": []}
        }),
        &[&chain_keys[17]],
    );
    chain_recs.push(obs16_rec);
    chain_recs.push(obs17_rec);

    let mut depth_opts = VerifyOptions::default();
    depth_opts.trusted_roots = Some([chain_keys[0].keyid.clone()].into_iter().collect());
    let depth_bundle = empty_bundle_with(
        chain_recs,
        vec![],
        chain_keys.iter().map(TestKey::key_json).collect(),
        vec![],
        vec![],
    );
    let depth_rep = verify_bundle_value(&depth_bundle, &depth_opts);
    assert_eq!(
        find_authority_finding(&depth_rep, &link16_ref)
            .unwrap()
            .code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&depth_rep, &obs16_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&depth_rep, &link17_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&depth_rep, &obs17_ref).unwrap().code,
        "not_covered"
    );
}

#[test]
fn a5_coverage_acts_for_on_behalf_of_actor_prefixes_stream_prefixes_and_seal_stream() {
    let root = TestKey::from_seed(80);
    let worker = TestKey::from_seed(81);
    let sealer = TestKey::from_seed(82);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let dummy_prof_ref = bytes_ref_of(b"prof");

    let (end_worker_ref, end_worker_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:auth-1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T12:00:00Z",
                "streamPrefixes": ["stream:work/"],
                "actorPrefixes": ["actor:agent/"],
                "actsFor": "user:carol"
            }
        }),
        &[&root],
    );

    // Sealer endorsed ONLY to seal `stream:work/` (even when seal record itself sits in `stream:seals`)
    let (end_sealer_ref, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:auth-2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T12:00:00Z",
                "streamPrefixes": ["stream:work/"]
            }
        }),
        &[&root],
    );

    // Matching record
    let (obs_ok_ref, obs_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:agent/one",
            "onBehalfOf": "user:carol",
            "stream": "stream:work/run1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {"topic": "ok", "contentRefs": []}
        }),
        &[&worker],
    );
    // Missing onBehalfOf
    let (obs_no_obo_ref, obs_no_obo_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:agent/one",
            "stream": "stream:work/run2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {"topic": "no-obo", "contentRefs": []}
        }),
        &[&worker],
    );
    // Actor outside actorPrefixes
    let (obs_bad_actor_ref, obs_bad_actor_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:outsider",
            "onBehalfOf": "user:carol",
            "stream": "stream:work/run3",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {"topic": "bad-actor", "contentRefs": []}
        }),
        &[&worker],
    );
    // Stream outside streamPrefixes
    let (obs_bad_stream_ref, obs_bad_stream_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:agent/one",
            "onBehalfOf": "user:carol",
            "stream": "stream:other/run4",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {"topic": "bad-stream", "contentRefs": []}
        }),
        &[&worker],
    );

    // Seal 1: envelope stream is `stream:seals-1` (outside `stream:work/`), `body.stream` is `stream:work/run1` (inside!) -> `ok`!
    let dummy_man_ref = bytes_ref_of(b"man");
    let dummy_root = format!("sha256:{}", "1".repeat(64));
    let (seal_ok_ref, seal_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seals-1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:15:00Z",
            "body": {
                "stream": "stream:work/run1",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": dummy_root,
                "manifestRef": dummy_man_ref
            }
        }),
        &[&sealer],
    );
    // Seal 2: envelope stream is `stream:work/seals` (inside `stream:work/`), `body.stream` is `stream:forbidden/run` (outside!) -> `not_covered`!
    let (seal_bad_ref, seal_bad_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:work/seals",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:15:00Z",
            "body": {
                "stream": "stream:forbidden/run",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": dummy_root,
                "manifestRef": dummy_man_ref
            }
        }),
        &[&sealer],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    let bundle = empty_bundle_with(
        vec![
            end_worker_rec,
            end_sealer_rec,
            obs_ok_rec,
            obs_no_obo_rec,
            obs_bad_actor_rec,
            obs_bad_stream_rec,
            seal_ok_rec,
            seal_bad_rec,
        ],
        vec![],
        vec![root.key_json(), worker.key_json(), sealer.key_json()],
        vec![],
        vec![],
    );
    let rep = verify_bundle_value(&bundle, &opts);

    assert_eq!(
        find_authority_finding(&rep, &obs_ok_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(end_worker_ref.as_str())
    );
    assert_eq!(
        find_authority_finding(&rep, &obs_no_obo_ref).unwrap().code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &obs_bad_actor_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &obs_bad_stream_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &seal_ok_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(end_sealer_ref.as_str())
    );
    assert_eq!(
        find_authority_finding(&rep, &seal_bad_ref).unwrap().code,
        "not_covered"
    );
}

#[test]
fn a5_successions_root_intermediate_badge_fork_cycle_16_step_cap_and_timestamps() {
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");
    let succ_sref = base_schema_ref("provenance.r5e.io/v2/Succession");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"prof");

    let mk_succ = |pred: &TestKey, succ: &TestKey, stream: &str, at: &str| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Succession",
                "schemaRef": succ_sref,
                "profileRef": dummy_prof_ref,
                "issuer": pred.keyid,
                "actor": "actor:key",
                "stream": stream,
                "seq": 1,
                "previous": null,
                "capturedAt": at,
                "body": {
                    "predecessor": pred.keyid,
                    "successor": succ.keyid,
                    "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(succ.pk)}
                }
            }),
            &[pred, succ],
        )
    };

    // Part A: Root succession (`root1 -> root2` at 11:00) + Badge subject succession (`w1 -> w2` at 10:30)
    let root1 = TestKey::from_seed(90);
    let root2 = TestKey::from_seed(91);
    let gw = TestKey::from_seed(92);
    let w1 = TestKey::from_seed(93);
    let w2 = TestKey::from_seed(94);

    // L0 issued by root1 at 10:00 (BEFORE root1 -> root2 at 11:00): trusted-root rule needs NO seal!
    let (l0_before_ref, l0_before_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root1.keyid,
            "actor": "actor:r1",
            "stream": "stream:r1-ok",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root1],
    );
    let (root_succ_ref, root_succ_rec) =
        mk_succ(&root1, &root2, "stream:r1-succ", "2026-11-10T11:00:00Z");

    // L0 issued by root1 at 11:05 (AFTER handover) -> `ended`!
    let (l0_r1_after_ref, l0_r1_after_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root1.keyid,
            "actor": "actor:r1",
            "stream": "stream:r1-after",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:05:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root1],
    );
    // L0 issued by root2 at 10:55 (BEFORE handover) -> `no_standing`; at 11:05 (AT/AFTER handover) -> `ok`!
    let (l0_r2_early_ref, l0_r2_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root2.keyid,
            "actor": "actor:r2",
            "stream": "stream:r2-early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:55:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root2],
    );
    let (l0_r2_ok_ref, l0_r2_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root2.keyid,
            "actor": "actor:r2",
            "stream": "stream:r2-ok",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:05:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T09:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root2],
    );
    // Work by gw at 12:00 under `l0_before` (issued by root1 before root1 handed over) remains `ok`!
    let (gw_obs_ref, gw_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:00:00Z",
            "body": {"topic": "still-valid", "contentRefs": []}
        }),
        &[&gw],
    );

    // Badge to w1, then w1 -> w2 at 10:30: badge dies with its key (`w2` gets `no_standing`, `w1` at 10:40 gets `ended`)!
    let (_, badge_w1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:badge-w1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {
                "subject": w1.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(w1.pk)},
                "holder": "worker",
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T13:00:00Z",
                "parent": l0_before_ref
            }
        }),
        &[&gw, &w1],
    );
    let (w_succ_ref, w_succ_rec) = mk_succ(&w1, &w2, "stream:w-succ", "2026-11-10T10:30:00Z");
    let (w2_obs_ref, w2_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": w2.keyid,
            "actor": "actor:w2",
            "stream": "stream:w2-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:40:00Z",
            "body": {"topic": "badge-does-not-pass", "contentRefs": []}
        }),
        &[&w2],
    );
    let (w1_obs_after_ref, w1_obs_after_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": w1.keyid,
            "actor": "actor:w1",
            "stream": "stream:w1-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:40:00Z",
            "body": {"topic": "predecessor-ended", "contentRefs": []}
        }),
        &[&w1],
    );

    let mut opts_a = VerifyOptions::default();
    opts_a.trusted_roots = Some([root1.keyid.clone()].into_iter().collect());
    let bundle_a = empty_bundle_with(
        vec![
            l0_before_rec,
            root_succ_rec,
            l0_r1_after_rec,
            l0_r2_early_rec,
            l0_r2_ok_rec,
            gw_obs_rec,
            badge_w1_rec,
            w_succ_rec,
            w2_obs_rec,
            w1_obs_after_rec,
        ],
        vec![],
        vec![
            root1.key_json(),
            root2.key_json(),
            gw.key_json(),
            w1.key_json(),
            w2.key_json(),
        ],
        vec![],
        vec![],
    );
    let rep_a = verify_bundle_value(&bundle_a, &opts_a);
    assert!(find_authority_finding(&rep_a, &root_succ_ref).is_none());
    assert_eq!(
        find_authority_finding(&rep_a, &l0_before_ref).unwrap().code,
        "ok"
    );
    // Under A6 Slice 2 §4.1, `Succession` never ends or transfers root standing:
    // `root1` remains active (`l0_r1_after_ref` is `ok`), and `root2` gets `no_standing`.
    assert_eq!(
        find_authority_finding(&rep_a, &l0_r1_after_ref)
            .unwrap()
            .code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &l0_r1_after_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(root1.keyid.as_str())
    );
    assert_eq!(
        find_authority_finding(&rep_a, &l0_r2_early_ref)
            .unwrap()
            .code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &l0_r2_ok_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &gw_obs_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &w2_obs_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &w1_obs_after_ref)
            .unwrap()
            .code,
        "ended"
    );
    assert_eq!(
        find_authority_finding(&rep_a, &w1_obs_after_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(w_succ_ref.as_str())
    );

    // Part B: Fork (`p -> f1` at 10:10, `p -> f2` at 10:20), Cycle (`c1 -> c2` at 10:10, `c2 -> c1` at 10:30),
    // and 16-step vs 17-step succession chain + "at or after every one on the way"!
    let root = TestKey::from_seed(100);
    let p_fork = TestKey::from_seed(101);
    let f1 = TestKey::from_seed(102);
    let f2 = TestKey::from_seed(103);
    let c1 = TestKey::from_seed(104);
    let c2 = TestKey::from_seed(105);
    let chain_s: Vec<TestKey> = (110..=127).map(TestKey::from_seed).collect(); // 18 keys: 0..=17

    let mk_end = |subj: &str, stream: &str| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Endorsement",
                "schemaRef": end_sref,
                "profileRef": dummy_prof_ref,
                "issuer": root.keyid,
                "actor": "actor:root",
                "stream": stream,
                "seq": 1,
                "previous": null,
                "capturedAt": "2026-11-10T10:00:00Z",
                "body": {
                    "subject": subj,
                    "kinds": ["provenance.r5e.io/v2/Observation"],
                    "mayEndorse": false,
                    "notBefore": "2026-11-10T09:00:00Z",
                    "notAfter": "2026-11-10T18:00:00Z"
                }
            }),
            &[&root],
        )
    };
    let mk_obs = |k: &TestKey, stream: &str, at: &str| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_sref,
                "profileRef": dummy_prof_ref,
                "issuer": k.keyid,
                "actor": "actor:k",
                "stream": stream,
                "seq": 1,
                "previous": null,
                "capturedAt": at,
                "body": {"topic": "t", "contentRefs": []}
            }),
            &[k],
        )
    };

    let (_, end_pfork_rec) = mk_end(&p_fork.keyid, "stream:end-pfork");
    let (_, end_c1_rec) = mk_end(&c1.keyid, "stream:end-c1");
    let (_, end_c2_rec) = mk_end(&c2.keyid, "stream:end-c2");
    let (end_s0_ref, end_s0_rec) = mk_end(&chain_s[0].keyid, "stream:end-s0");

    let (fork1_ref, fork1_rec) = mk_succ(&p_fork, &f1, "stream:fork1", "2026-11-10T10:10:00Z");
    let (_, fork2_rec) = mk_succ(&p_fork, &f2, "stream:fork2", "2026-11-10T10:20:00Z");
    let (pfork_obs_ref, pfork_obs_rec) =
        mk_obs(&p_fork, "stream:pfork-obs", "2026-11-10T10:15:00Z");
    let (f1_obs_ref, f1_obs_rec) = mk_obs(&f1, "stream:f1-obs", "2026-11-10T10:25:00Z");
    let (f2_obs_ref, f2_obs_rec) = mk_obs(&f2, "stream:f2-obs", "2026-11-10T10:25:00Z");

    let (cyc1_ref, cyc1_rec) = mk_succ(&c1, &c2, "stream:cyc1", "2026-11-10T10:10:00Z");
    let (_, cyc2_rec) = mk_succ(&c2, &c1, "stream:cyc2", "2026-11-10T10:30:00Z");
    // c2 at 10:20 (between 10:10 and 10:30) is STILL ended from 10:10 (`cyc1_ref`, earliest in cycle)!
    let (c2_obs_mid_ref, c2_obs_mid_rec) = mk_obs(&c2, "stream:c2-mid", "2026-11-10T10:20:00Z");

    let mut recs_b = vec![
        end_pfork_rec,
        end_c1_rec,
        end_c2_rec,
        end_s0_rec,
        fork1_rec,
        fork2_rec,
        pfork_obs_rec,
        f1_obs_rec,
        f2_obs_rec,
        cyc1_rec,
        cyc2_rec,
        c2_obs_mid_rec,
    ];
    // Step 0 -> 1 dated 11:00, steps 1 -> 2 .. 15 -> 16 dated 10:30 (16 steps total, chain_s[16] terminal):
    // Signing at 10:45 with chain_s[2] fails because 10:45 < 11:00 (must be >= EVERY handover on the way)!
    // Signing at 11:05 with terminal chain_s[16] (16 steps) succeeds (`ok`).
    for idx in 0..16 {
        let ts = if idx == 0 {
            "2026-11-10T11:00:00Z"
        } else {
            "2026-11-10T10:30:00Z"
        };
        let (_, srec) = mk_succ(
            &chain_s[idx],
            &chain_s[idx + 1],
            &format!("stream:sc-{idx}"),
            ts,
        );
        recs_b.push(srec);
    }
    let (s2_early_ref, s2_early_rec) =
        mk_obs(&chain_s[2], "stream:s2-early", "2026-11-10T10:45:00Z");
    let (s16_ok_ref, s16_ok_rec) = mk_obs(&chain_s[16], "stream:s16-ok", "2026-11-10T11:05:00Z");
    recs_b.extend([s2_early_rec, s16_ok_rec]);

    let mut keys_b = vec![
        root.key_json(),
        p_fork.key_json(),
        f1.key_json(),
        f2.key_json(),
        c1.key_json(),
        c2.key_json(),
    ];
    keys_b.extend(chain_s.iter().map(TestKey::key_json));

    let mut opts_b = VerifyOptions::default();
    opts_b.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    let bundle_b = empty_bundle_with(recs_b.clone(), vec![], keys_b.clone(), vec![], vec![]);
    let rep_b = verify_bundle_value(&bundle_b, &opts_b);

    // Fork assertions
    assert_eq!(
        find_authority_finding(&rep_b, &pfork_obs_ref).unwrap().code,
        "ended"
    );
    assert_eq!(
        find_authority_finding(&rep_b, &pfork_obs_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(fork1_ref.as_str())
    );
    assert_eq!(
        find_authority_finding(&rep_b, &f1_obs_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_b, &f2_obs_ref).unwrap().code,
        "no_standing"
    );

    // Cycle assertions
    assert_eq!(
        find_authority_finding(&rep_b, &c2_obs_mid_ref)
            .unwrap()
            .code,
        "ended"
    );
    assert_eq!(
        find_authority_finding(&rep_b, &c2_obs_mid_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(cyc1_ref.as_str())
    );

    // Chain timestamp & 16-step terminal assertions
    assert_eq!(
        find_authority_finding(&rep_b, &s2_early_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_b, &s16_ok_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep_b, &s16_ok_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(end_s0_ref.as_str())
    );

    // Adding a 17th step (16 -> 17): chain_s[17] exceeds the 16-step cap (`no_standing`),
    // and chain_s[16] is now ended by the 16 -> 17 handover (`ended`).
    let (succ_16_17_ref, succ_16_17_rec) = mk_succ(
        &chain_s[16],
        &chain_s[17],
        "stream:sc-16",
        "2026-11-10T10:30:00Z",
    );
    let (s17_cap_ref, s17_cap_rec) = mk_obs(&chain_s[17], "stream:s17-cap", "2026-11-10T11:05:00Z");
    let mut recs_b17 = recs_b;
    recs_b17.extend([succ_16_17_rec, s17_cap_rec]);
    let bundle_b17 = empty_bundle_with(recs_b17, vec![], keys_b, vec![], vec![]);
    let rep_b17 = verify_bundle_value(&bundle_b17, &opts_b);
    assert_eq!(
        find_authority_finding(&rep_b17, &s17_cap_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_b17, &s16_ok_ref).unwrap().code,
        "ended"
    );
    assert_eq!(
        find_authority_finding(&rep_b17, &s16_ok_ref)
            .unwrap()
            .about
            .as_deref(),
        Some(succ_16_17_ref.as_str())
    );
}

#[test]
fn a5_revocations_and_self_vs_above_endings_with_corroborating_seals() {
    let root = TestKey::from_seed(140);
    let root2 = TestKey::from_seed(141);
    let gw = TestKey::from_seed(142);
    let gw_succ = TestKey::from_seed(143);
    let worker = TestKey::from_seed(144);
    let sealer = TestKey::from_seed(145);
    let bad_sealer = TestKey::from_seed(146);
    let stranger = TestKey::from_seed(147);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");
    let succ_sref = base_schema_ref("provenance.r5e.io/v2/Succession");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let dummy_prof_ref = bytes_ref_of(b"prof");

    // Root endorses gw, and root endorses sealer (and root LATER hands over to root2 at 15:00 — sealer still counts!)
    let (end_gw_ref, end_gw_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-gw",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-sealer",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T18:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, root_succ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-succ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T15:00:00Z",
            "body": {
                "predecessor": root.keyid,
                "successor": root2.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root2.pk)}
            }
        }),
        &[&root, &root2],
    );

    // Badge B1 (revoked by ancestor `root`), Badge B2 (revoked by successor `gw_succ` of `gw`),
    // Badge B3 (self-revoked by subject `worker`, backdated before honest sealed record!)
    let mk_badge = |stream: &str| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Badge",
                "schemaRef": badge_sref,
                "profileRef": dummy_prof_ref,
                "issuer": gw.keyid,
                "actor": "actor:gw",
                "stream": stream,
                "seq": 1,
                "previous": null,
                "capturedAt": "2026-11-10T10:05:00Z",
                "body": {
                    "subject": worker.keyid,
                    "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(worker.pk)},
                    "holder": "worker",
                    "kinds": ["provenance.r5e.io/v2/Observation"],
                    "notBefore": "2026-11-10T10:05:00Z",
                    "notAfter": "2026-11-10T14:00:00Z",
                    "parent": end_gw_ref
                }
            }),
            &[&gw, &worker],
        )
    };
    let (b1_ref, b1_rec) = mk_badge("stream:b1");
    let (b2_ref, b2_rec) = mk_badge("stream:b2");

    // Ancestor `root` revokes `b1` at 10:20; `gw -> gw_succ` at 10:15 and `gw_succ` revokes `b2` at 10:20
    let (rev_anc_ref, rev_anc_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:rev-anc",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:20:00Z",
            "body": {"target": b1_ref}
        }),
        &[&root],
    );
    let (_, gw_succ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-succ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:15:00Z",
            "body": {
                "predecessor": gw.keyid,
                "successor": gw_succ.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(gw_succ.pk)}
            }
        }),
        &[&gw, &gw_succ],
    );
    let (rev_succ_ref, rev_succ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw_succ.keyid,
            "actor": "actor:gw-succ",
            "stream": "stream:rev-succ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:20:00Z",
            "body": {"target": b2_ref}
        }),
        &[&gw_succ],
    );

    // Revocation edge cases: stranger revoking `b1` (`no_standing`), missing target (`chain_not_carried`), non-grant target (`not_covered`)
    let (obs_plain_ref, obs_plain_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:obs-after-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:25:00Z",
            "body": {"topic": "after-both-revs", "contentRefs": []}
        }),
        &[&worker],
    );
    let (rev_stranger_ref, rev_stranger_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "stream:rev-stranger",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:06:00Z",
            "body": {"target": b1_ref}
        }),
        &[&stranger],
    );
    let missing_target = format!("evidence:sha256:{}", "b".repeat(64));
    let (rev_missing_ref, rev_missing_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:rev-missing",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:06:00Z",
            "body": {"target": missing_target}
        }),
        &[&root],
    );
    let (rev_nongrant_ref, rev_nongrant_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:rev-nongrant",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:30:00Z",
            "body": {"target": obs_plain_ref}
        }),
        &[&root],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    let bundle1 = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            end_sealer_rec.clone(),
            root_succ_rec.clone(),
            b1_rec,
            b2_rec,
            rev_anc_rec,
            gw_succ_rec,
            rev_succ_rec,
            obs_plain_rec,
            rev_stranger_rec,
            rev_missing_rec,
            rev_nongrant_rec,
        ],
        vec![],
        vec![
            root.key_json(),
            root2.key_json(),
            gw.key_json(),
            gw_succ.key_json(),
            worker.key_json(),
            sealer.key_json(),
            stranger.key_json(),
        ],
        vec![],
        vec![],
    );
    let rep1 = verify_bundle_value(&bundle1, &opts);
    assert_eq!(
        find_authority_finding(&rep1, &rev_anc_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep1, &rev_succ_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep1, &rev_stranger_ref)
            .unwrap()
            .code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep1, &rev_missing_ref)
            .unwrap()
            .code,
        "chain_not_carried"
    );
    assert_eq!(
        find_authority_finding(&rep1, &rev_nongrant_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    // Both b1 and b2 ended before obs_plain (10:25 >= 10:20); tie-break picks lowest ending ref in byte order!
    let expected_min_rev = std::cmp::min(rev_anc_ref.as_str(), rev_succ_ref.as_str());
    let obs_f = find_authority_finding(&rep1, &obs_plain_ref).unwrap();
    assert_eq!(obs_f.code, "ended");
    assert_eq!(obs_f.about.as_deref(), Some(expected_min_rev));

    // Part B: Self-signed ending (subject revocation) vs sealed honest history,
    // plus seal by unknown key (`bad_sealer`) not counting!
    let (b3_ref, b3_rec) = mk_badge("stream:b3");
    // Honest record at 12:00, sealed at 12:05 by `sealer` (via membership proof!), while subject `worker`
    // signs a backdated self-revocation claiming 11:00 (`e = 11:00 < t = 12:00`, `e < s = 12:05`)!
    let (honest_obs_ref, honest_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:honest",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:00:00Z",
            "body": {"topic": "june-history", "contentRefs": []}
        }),
        &[&worker],
    );
    // Early record at 10:30 (`t < e = 11:00`), sealed at 10:40 (`s < e = 11:00`) -> `ShownToPrecede` (`ok`)!
    let (early_obs_ref, early_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:30:00Z",
            "body": {"topic": "early-history", "contentRefs": []}
        }),
        &[&worker],
    );
    // Unsealed record at 10:35 (`t < e = 11:00`) sealed ONLY by `bad_sealer` (no standing!) -> `time_rests_on_the_signer`!
    let (bad_sealed_obs_ref, bad_sealed_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:bad-sealed",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:35:00Z",
            "body": {"topic": "bad-sealer-only", "contentRefs": []}
        }),
        &[&worker],
    );
    let (self_rev_ref, self_rev_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:self-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": b3_ref}
        }),
        &[&worker],
    );

    let digest_of = |r: &str| {
        r5e_verify_rs::provenance_v2::canonical::decode_hex_32(
            r.strip_prefix("evidence:sha256:").unwrap(),
        )
        .unwrap()
    };

    // Seal `honest_obs_rec` via membership proof ONLY (manifest omitted) at 12:05 by `sealer`
    let honest_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&honest_obs_ref)]))
    );
    let (seal_honest_ref, seal_honest_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-honest",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:05:00Z",
            "body": {
                "stream": "stream:honest",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": honest_root,
                "manifestRef": bytes_ref_of(b"omitted-manifest")
            }
        }),
        &[&sealer],
    );
    let honest_proof = json!({
        "record": honest_obs_ref,
        "seal": seal_honest_ref,
        "index": 0,
        "siblings": []
    });

    // Seal `early_obs_rec` at 10:40 (< 11:00) by `sealer`
    let early_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&early_obs_ref)]))
    );
    let (man_early_ref, man_early_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [early_obs_ref]
    }));
    let (seal_early_ref, seal_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:40:00Z",
            "body": {
                "stream": "stream:early",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": early_root,
                "manifestRef": man_early_ref
            }
        }),
        &[&sealer],
    );

    // Seal `bad_sealed_obs_rec` at 10:40 (< 11:00) by `bad_sealer` (no standing!)
    let bad_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&bad_sealed_obs_ref)]))
    );
    let (man_bad_ref, man_bad_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [bad_sealed_obs_ref]
    }));
    let (seal_bad_ref, seal_bad_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": bad_sealer.keyid,
            "actor": "actor:bad-sealer",
            "stream": "stream:seal-bad",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:40:00Z",
            "body": {
                "stream": "stream:bad-sealed",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": bad_root,
                "manifestRef": man_bad_ref
            }
        }),
        &[&bad_sealer],
    );

    let bundle2 = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            end_sealer_rec.clone(),
            root_succ_rec.clone(),
            b3_rec.clone(),
            honest_obs_rec.clone(),
            early_obs_rec,
            bad_sealed_obs_rec,
            self_rev_rec.clone(),
            seal_honest_rec.clone(),
            seal_early_rec,
            seal_bad_rec,
        ],
        vec![man_early_blob, man_bad_blob],
        vec![
            root.key_json(),
            root2.key_json(),
            gw.key_json(),
            worker.key_json(),
            sealer.key_json(),
            bad_sealer.key_json(),
        ],
        vec![json!(seal_early_ref), json!(seal_bad_ref)],
        vec![honest_proof.clone()],
    );
    let rep2 = verify_bundle_value(&bundle2, &opts);

    assert_eq!(
        find_authority_finding(&rep2, &self_rev_ref).unwrap().code,
        "ok"
    );
    // Early record sealed before 11:00 by `sealer` (whose root later handed over at 15:00!) -> `ok`!
    assert_eq!(
        find_authority_finding(&rep2, &early_obs_ref).unwrap().code,
        "ok"
    );
    // Record sealed only by `bad_sealer` (no standing) -> `time_rests_on_the_signer`!
    assert_eq!(
        find_authority_finding(&rep2, &bad_sealed_obs_ref)
            .unwrap()
            .code,
        "time_rests_on_the_signer"
    );
    // Honest record at 12:00 (>= 11:00) sealed at 12:05 while self-revocation is unsealed -> `time_rests_on_the_signer`, NOT `ended`!
    let honest_f = find_authority_finding(&rep2, &honest_obs_ref).unwrap();
    assert_eq!(
        (&honest_f.result[..], &honest_f.code[..]),
        ("incomplete", "time_rests_on_the_signer")
    );
    assert_eq!(honest_f.about.as_deref(), Some(self_rev_ref.as_str()));

    // Now ALSO seal `self_rev_rec` at 11:05 (`sE = 11:05 <= s = 12:05`) -> `s` is no longer first, so `ended`!
    let rev_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&self_rev_ref)]))
    );
    let (man_rev_ref, man_rev_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [self_rev_ref]
    }));
    let (seal_rev_ref, seal_rev_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:05:00Z",
            "body": {
                "stream": "stream:self-rev",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": rev_root,
                "manifestRef": man_rev_ref
            }
        }),
        &[&sealer],
    );
    let bundle3 = empty_bundle_with(
        vec![
            end_gw_rec,
            end_sealer_rec,
            root_succ_rec,
            b3_rec,
            honest_obs_rec,
            self_rev_rec,
            seal_honest_rec,
            seal_rev_rec,
        ],
        vec![man_rev_blob],
        vec![
            root.key_json(),
            root2.key_json(),
            gw.key_json(),
            worker.key_json(),
            sealer.key_json(),
        ],
        vec![json!(seal_rev_ref)],
        vec![honest_proof],
    );
    let rep3 = verify_bundle_value(&bundle3, &opts);
    assert_eq!(
        find_authority_finding(&rep3, &honest_obs_ref).unwrap().code,
        "ended"
    );
}

#[test]
fn a5_cli_trusted_root_establish_authority_and_wasm_ffi_options() {
    let case_dir = vectors_cases_dir().join("authority-root-to-badge");
    let case_meta: Value =
        serde_json::from_slice(&fs::read(case_dir.join("case.json")).unwrap()).unwrap();
    let bundle_path = case_dir.join("bundle.json");
    let bundle_bytes = fs::read(&bundle_path).unwrap();
    let expected: Value =
        serde_json::from_slice(&fs::read(case_dir.join("expected-report.json")).unwrap()).unwrap();

    let trusted_profile = case_meta["trustedProfiles"][0].as_str().unwrap();
    let trusted_root = case_meta["trustedRoots"][0].as_str().unwrap();

    // 1. CLI with `--trusted-root` and `--trusted-profile` + `--allow-incomplete` (publication is incomplete in this vector)
    let out = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
        .arg(&bundle_path)
        .args(["--trusted-profile", trusted_profile])
        .args(["--trusted-root", trusted_root])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let cli_rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(cli_rep, expected);

    // 2. CLI with `--establish-authority` (Some(empty)): root endorsement gets `failed` / `no_standing`, exit 1
    let out_empty = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
        .arg(&bundle_path)
        .args([
            "--trusted-profile",
            trusted_profile,
            "--establish-authority",
        ])
        .output()
        .unwrap();
    assert_eq!(out_empty.status.code(), Some(1));
    let empty_rep: Value = serde_json::from_slice(&out_empty.stdout).unwrap();
    assert!(
        empty_rep["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["check"] == "authority" && f["code"] == "no_standing")
    );

    // 3. WASM FFI `trustedRoots`: absent/`null` -> §6.3 profile authority; `[]` -> Some(empty); `[root]` -> matches vector!
    for null_opts in [
        json!({"trustedProfiles": [trusted_profile]}),
        json!({"trustedProfiles": [trusted_profile], "trustedRoots": null}),
    ] {
        let ffi_out: Value = serde_json::from_slice(
            &r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes(
                &bundle_bytes,
                &serde_json::to_vec(&null_opts).unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(ffi_out["ok"], true);
        assert!(
            ffi_out["report"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["check"] == "authority")
                .all(|f| f["about"] == trusted_profile)
        );
    }

    let ffi_empty: Value = serde_json::from_slice(
        &r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes(
            &bundle_bytes,
            &serde_json::to_vec(&json!({
                "trustedProfiles": [trusted_profile],
                "trustedRoots": []
            }))
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(ffi_empty["exitCode"], 1);
    assert_eq!(ffi_empty["report"], empty_rep);

    let ffi_match: Value = serde_json::from_slice(
        &r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes(
            &bundle_bytes,
            &serde_json::to_vec(&json!({
                "trustedProfiles": [trusted_profile],
                "trustedRoots": [trusted_root]
            }))
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(ffi_match["report"], expected);
}

fn digest_of(r: &str) -> [u8; 32] {
    r5e_verify_rs::provenance_v2::canonical::decode_hex_32(
        r.strip_prefix("evidence:sha256:").unwrap(),
    )
    .unwrap()
}

#[test]
fn a5_revocation_by_handed_over_key_with_and_without_pre_handover_seal() {
    let root = TestKey::from_seed(140);
    let root2 = TestKey::from_seed(141);
    let gw = TestKey::from_seed(142);
    let gw2 = TestKey::from_seed(143);
    let worker = TestKey::from_seed(144);
    let sealer = TestKey::from_seed(145);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");
    let succ_sref = base_schema_ref("provenance.r5e.io/v2/Succession");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let dummy_prof_ref = bytes_ref_of(b"prof-handover-rev");

    // Root endorses Gateway (`mayEndorse: true`) and Sealer (`EpochSeal`).
    let (end_gw_ref, end_gw_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": gw.keyid,
                "kinds": [
                    "provenance.r5e.io/v2/Observation",
                    "provenance.r5e.io/v2/EpochSeal"
                ],
                "mayEndorse": true,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T15:00:00Z"
            }
        }),
        &[&root],
    );
    let (_end_sealer_ref, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-sealer",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T15:00:00Z"
            }
        }),
        &[&root],
    );

    // Gateway issues Badge to Worker at 10:05; Gateway seals its grant via Sealer at 10:10 so Gateway's
    // issuance of `b_worker` stands even after Gateway hands over at 12:00!
    let (b_worker_ref, b_worker_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-badge",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:05:00Z",
            "body": {
                "subject": worker.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(worker.pk)},
                "holder": "worker",
                "parent": end_gw_ref,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "notBefore": "2026-11-10T10:05:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&gw, &worker],
    );
    let badge_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&b_worker_ref)]))
    );
    let (man_badge_ref, man_badge_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [b_worker_ref]
    }));
    let (seal_badge_ref, seal_badge_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-badge",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {
                "stream": "stream:gw-badge",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": badge_root,
                "manifestRef": man_badge_ref
            }
        }),
        &[&sealer],
    );

    // Gateway hands over to gw2 at 12:00.
    let (_gw_succ_ref, gw_succ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-succ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:00:00Z",
            "body": {
                "predecessor": gw.keyid,
                "successor": gw2.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(gw2.pk)}
            }
        }),
        &[&gw, &gw2],
    );

    // Gateway signs a Revocation of `b_worker` claiming timestamp 11:00 (< 12:00).
    let (rev_gw_ref, rev_gw_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": b_worker_ref}
        }),
        &[&gw],
    );

    // Worker signs an Observation at 11:30 (>= 11:00).
    let (obs_ref, obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:worker-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:30:00Z",
            "body": {"topic": "post-rev", "contentRefs": []}
        }),
        &[&worker],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    let all_keys = vec![
        root.key_json(),
        root2.key_json(),
        gw.key_json(),
        gw2.key_json(),
        worker.key_json(),
        sealer.key_json(),
    ];

    // 1. Unsealed revocation by handed-over non-root `gw` -> `no_standing`, `obs` stays `ok`!
    let b_unsealed = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            end_sealer_rec.clone(),
            b_worker_rec.clone(),
            seal_badge_rec.clone(),
            gw_succ_rec.clone(),
            rev_gw_rec.clone(),
            obs_rec.clone(),
        ],
        vec![man_badge_blob.clone()],
        all_keys.clone(),
        vec![json!(seal_badge_ref)],
        vec![],
    );
    let rep_unsealed = verify_bundle_value(&b_unsealed, &opts);
    assert_eq!(
        find_authority_finding(&rep_unsealed, &rev_gw_ref)
            .unwrap()
            .code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_unsealed, &obs_ref)
            .unwrap()
            .code,
        "ok"
    );

    // 2. Sealed AFTER handover (`12:05 >= 12:00`) -> still `no_standing`, `obs` stays `ok`!
    let rev_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&rev_gw_ref)]))
    );
    let (man_rev_ref, man_rev_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [rev_gw_ref]
    }));
    let (seal_late_ref, seal_late_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-late",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:05:00Z",
            "body": {
                "stream": "stream:gw-rev",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": rev_root,
                "manifestRef": man_rev_ref
            }
        }),
        &[&sealer],
    );
    let b_late = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            end_sealer_rec.clone(),
            b_worker_rec.clone(),
            seal_badge_rec.clone(),
            gw_succ_rec.clone(),
            rev_gw_rec.clone(),
            obs_rec.clone(),
            seal_late_rec,
        ],
        vec![man_badge_blob.clone(), man_rev_blob.clone()],
        all_keys.clone(),
        vec![json!(seal_badge_ref), json!(seal_late_ref)],
        vec![],
    );
    let rep_late = verify_bundle_value(&b_late, &opts);
    assert_eq!(
        find_authority_finding(&rep_late, &rev_gw_ref).unwrap().code,
        "no_standing"
    );
    assert_eq!(
        find_authority_finding(&rep_late, &obs_ref).unwrap().code,
        "ok"
    );

    // 3. Sealed BEFORE handover (`11:15 < 12:00`) -> `rev_gw` is `ok` and `obs` (`11:30`) is `ended`!
    let (seal_early_ref, seal_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:15:00Z",
            "body": {
                "stream": "stream:gw-rev",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": rev_root,
                "manifestRef": man_rev_ref
            }
        }),
        &[&sealer],
    );
    let b_early = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            end_sealer_rec,
            b_worker_rec,
            seal_badge_rec,
            gw_succ_rec.clone(),
            rev_gw_rec,
            obs_rec,
            seal_early_rec,
        ],
        vec![man_badge_blob, man_rev_blob],
        all_keys.clone(),
        vec![json!(seal_badge_ref), json!(seal_early_ref)],
        vec![],
    );
    let rep_early = verify_bundle_value(&b_early, &opts);
    let rev_f = find_authority_finding(&rep_early, &rev_gw_ref).unwrap();
    assert_eq!((&rev_f.result[..], &rev_f.code[..]), ("ok", "ok"));
    assert_eq!(rev_f.about.as_deref(), Some(b_worker_ref.as_str()));
    let obs_f = find_authority_finding(&rep_early, &obs_ref).unwrap();
    assert_eq!((&obs_f.result[..], &obs_f.code[..]), ("failed", "ended"));
    assert_eq!(obs_f.about.as_deref(), Some(rev_gw_ref.as_str()));

    // 4. Non-circularity (§6 Condition 3): if `gw` (handed over at 12:00) revokes `sealer`'s ONLY grant
    // (`b_sub_sealer` issued by `gw`), and `sealer` itself signs the only seal over that revocation at 11:15,
    // activating the revocation would strip `sealer` of standing at all times, so the circular seal fails!
    let sub_sealer = TestKey::from_seed(146);
    let (b_sub_sealer_ref, b_sub_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-sealer-badge",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:05:00Z",
            "body": {
                "subject": sub_sealer.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(sub_sealer.pk)},
                "holder": "sub-sealer",
                "parent": end_gw_ref,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "notBefore": "2026-11-10T10:05:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&gw, &sub_sealer],
    );
    let (rev_circ_ref, rev_circ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": gw.keyid,
            "actor": "actor:gw",
            "stream": "stream:gw-rev-circ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": b_sub_sealer_ref}
        }),
        &[&gw],
    );
    let circ_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&b_sub_sealer_ref)]))
    );
    let (man_sub_ref, man_sub_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [b_sub_sealer_ref]
    }));
    let (seal_sub_ref, seal_sub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sub_sealer.keyid,
            "actor": "actor:sub-sealer",
            "stream": "stream:seal-sub",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:10:00Z",
            "body": {
                "stream": "stream:gw-sealer-badge",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": circ_root,
                "manifestRef": man_sub_ref
            }
        }),
        &[&sub_sealer],
    );
    let rev_circ_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&rev_circ_ref)]))
    );
    let (man_rc_ref, man_rc_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [rev_circ_ref]
    }));
    let (seal_rc_ref, seal_rc_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sub_sealer.keyid,
            "actor": "actor:sub-sealer",
            "stream": "stream:seal-rc",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:15:00Z",
            "body": {
                "stream": "stream:gw-rev-circ",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": rev_circ_root,
                "manifestRef": man_rc_ref
            }
        }),
        &[&sub_sealer],
    );
    let mut keys_with_sub = all_keys.clone();
    keys_with_sub.push(sub_sealer.key_json());
    let b_circ = empty_bundle_with(
        vec![
            end_gw_rec.clone(),
            gw_succ_rec,
            b_sub_sealer_rec,
            rev_circ_rec,
            seal_sub_rec,
            seal_rc_rec,
        ],
        vec![man_sub_blob, man_rc_blob],
        keys_with_sub,
        vec![json!(seal_sub_ref), json!(seal_rc_ref)],
        vec![],
    );
    let rep_circ = verify_bundle_value(&b_circ, &opts);
    assert_eq!(
        find_authority_finding(&rep_circ, &rev_circ_ref)
            .unwrap()
            .code,
        "no_standing"
    );

    // 5. Trusted root handing over at 12:00: root's own `capturedAt < 12:00` revokes without a seal,
    // while `capturedAt >= 12:00` fails `no_standing`!
    let (_root_succ_ref, root_succ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-succ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:00:00Z",
            "body": {
                "predecessor": root.keyid,
                "successor": root2.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root2.pk)}
            }
        }),
        &[&root, &root2],
    );
    let (root_rev_early_ref, root_rev_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-rev-1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": end_gw_ref}
        }),
        &[&root],
    );
    let (root_rev_late_ref, root_rev_late_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:root-rev-2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T12:00:00Z",
            "body": {"target": end_gw_ref}
        }),
        &[&root],
    );
    let b_root_rev = empty_bundle_with(
        vec![
            end_gw_rec,
            root_succ_rec,
            root_rev_early_rec,
            root_rev_late_rec,
        ],
        vec![],
        all_keys,
        vec![],
        vec![],
    );
    let rep_root_rev = verify_bundle_value(&b_root_rev, &opts);
    // Under A6 Slice 2 §4.1, `Succession` never ends a root, so both revocations by `root` remain `ok`.
    assert_eq!(
        find_authority_finding(&rep_root_rev, &root_rev_early_ref)
            .unwrap()
            .code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep_root_rev, &root_rev_late_ref)
            .unwrap()
            .code,
        "ok"
    );
}

#[test]
fn a5_five_row_revocation_loop_lead_in_and_link_own_authority_rules() {
    let root = TestKey::from_seed(150);
    let mid = TestKey::from_seed(151);
    let leaf = TestKey::from_seed(152);
    let sealer = TestKey::from_seed(153);
    let key_a = TestKey::from_seed(154);
    let key_b = TestKey::from_seed(155);
    let unknown_iss = TestKey::from_seed(156);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");
    let succ_sref = base_schema_ref("provenance.r5e.io/v2/Succession");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let dummy_prof_ref = bytes_ref_of(b"prof-bcbcc72");

    // 1. Five-row `Revocation` table:
    // - `l1` names an uncarried `parent` (`missing_l0_ref`).
    // - `b_leaf` names `parent = l1`.
    // - `root` revoking `b_leaf` -> Row 2 (`incomplete` / `chain_not_carried`, `about = missing_l0_ref`).
    // - `mid` (`b_leaf.issuer`) revoking `b_leaf` -> Row 1 (`ok`, `about = b_leaf_ref`).
    // - `root` revoking an Endorsement whose signer key is omitted (`missing_key`) -> Row 4 (`chain_not_carried`, `about = target`).
    let missing_l0_ref = evidence_ref_of(b"uncarried-top-endorsement");
    let (l1_ref, l1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": mid.keyid,
            "actor": "actor:mid",
            "stream": "stream:mid-l1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:01:00Z",
            "body": {
                "subject": mid.keyid,
                "parent": missing_l0_ref,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&mid],
    );
    // Note: `l1` above is self-endorsement if `subject == mid`; use a distinct intermediate `sub_mid`!
    let _ = (l1_ref, l1_rec);
    let sub_mid = TestKey::from_seed(157);
    let (l1_valid_ref, l1_valid_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": mid.keyid,
            "actor": "actor:mid",
            "stream": "stream:mid-l1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:01:00Z",
            "body": {
                "subject": sub_mid.keyid,
                "parent": missing_l0_ref,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": true,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&mid],
    );
    let (b_leaf_ref, b_leaf_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sub_mid.keyid,
            "actor": "actor:sub-mid",
            "stream": "stream:leaf-badge",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:02:00Z",
            "body": {
                "subject": leaf.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(leaf.pk)},
                "holder": "leaf",
                "parent": l1_valid_ref,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&sub_mid, &leaf],
    );
    let (rev_by_root_ref, rev_by_root_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:rev-root",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": b_leaf_ref}
        }),
        &[&root],
    );
    let (rev_by_issuer_ref, rev_by_issuer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sub_mid.keyid,
            "actor": "actor:sub-mid",
            "stream": "stream:rev-iss",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": b_leaf_ref}
        }),
        &[&sub_mid],
    );
    let (end_missing_key_ref, end_missing_key_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": unknown_iss.keyid,
            "actor": "actor:unknown",
            "stream": "stream:unknown",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": leaf.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&unknown_iss],
    );
    let (rev_mk_target_ref, rev_mk_target_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:rev-mk",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {"target": end_missing_key_ref}
        }),
        &[&root],
    );

    // 2. Link own-authority with failed `body` (`notBefore > notAfter` -> `not_covered`) vs forged signature (`ok` on root's alleged link, `not_covered` on child Badge).
    let (bad_body_end_ref, bad_body_end_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:bad-body",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": leaf.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T14:00:00Z",
                "notAfter": "2026-11-10T10:00:00Z"
            }
        }),
        &[&root],
    );

    // 3. Succession loop with lead-in (`mid -> key_a` at 10:05, `key_a -> key_b` at 11:00, `key_b -> key_a` at 11:10):
    // `root` endorses `mid` and `sealer`; `key_a` signs an Observation at 10:20 sealed at 10:30 (< 11:00),
    // which stands (`ok`), while `key_a` at 11:20 is `ended` and `key_b` at 11:20 is `no_standing`!
    let (_end_mid_ref, end_mid_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-mid",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": mid.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&root],
    );
    let (_end_sealer_ref, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-sealer",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:00:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-10T10:00:00Z",
                "notAfter": "2026-11-10T14:00:00Z"
            }
        }),
        &[&root],
    );
    let (_s_lead_ref, s_lead_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": mid.keyid,
            "actor": "actor:mid",
            "stream": "stream:s-lead",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:05:00Z",
            "body": {
                "predecessor": mid.keyid,
                "successor": key_a.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(key_a.pk)}
            }
        }),
        &[&mid, &key_a],
    );
    let (s_ab_ref, s_ab_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": key_a.keyid,
            "actor": "actor:a",
            "stream": "stream:s-ab",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:00:00Z",
            "body": {
                "predecessor": key_a.keyid,
                "successor": key_b.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(key_b.pk)}
            }
        }),
        &[&key_a, &key_b],
    );
    let (_s_ba_ref, s_ba_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": succ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": key_b.keyid,
            "actor": "actor:b",
            "stream": "stream:s-ba",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:10:00Z",
            "body": {
                "predecessor": key_b.keyid,
                "successor": key_a.keyid,
                "successorKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(key_a.pk)}
            }
        }),
        &[&key_b, &key_a],
    );
    let (obs_a_early_ref, obs_a_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": key_a.keyid,
            "actor": "actor:a",
            "stream": "stream:a-early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:20:00Z",
            "body": {"topic": "before-loop", "contentRefs": []}
        }),
        &[&key_a],
    );
    let a_early_root = format!(
        "sha256:{}",
        hex_encode(&merkle_root(&[digest_of(&obs_a_early_ref)]))
    );
    let (man_a_ref, man_a_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [obs_a_early_ref]
    }));
    let (seal_a_ref, seal_a_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-a",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T10:30:00Z",
            "body": {
                "stream": "stream:a-early",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": a_early_root,
                "manifestRef": man_a_ref
            }
        }),
        &[&sealer],
    );
    let (obs_a_late_ref, obs_a_late_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": key_a.keyid,
            "actor": "actor:a",
            "stream": "stream:a-late",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:20:00Z",
            "body": {"topic": "after-loop", "contentRefs": []}
        }),
        &[&key_a],
    );
    let (obs_b_ref, obs_b_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": key_b.keyid,
            "actor": "actor:b",
            "stream": "stream:b-obs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-10T11:20:00Z",
            "body": {"topic": "in-loop", "contentRefs": []}
        }),
        &[&key_b],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    // Intentionally omit `unknown_iss.key_json()` so `end_missing_key_rec` has `missing_key`!
    let bundle = empty_bundle_with(
        vec![
            l1_valid_rec,
            b_leaf_rec,
            rev_by_root_rec,
            rev_by_issuer_rec,
            end_missing_key_rec,
            rev_mk_target_rec,
            bad_body_end_rec,
            end_mid_rec,
            end_sealer_rec,
            s_lead_rec,
            s_ab_rec,
            s_ba_rec,
            obs_a_early_rec,
            seal_a_rec,
            obs_a_late_rec,
            obs_b_rec,
        ],
        vec![man_a_blob],
        vec![
            root.key_json(),
            mid.key_json(),
            sub_mid.key_json(),
            leaf.key_json(),
            sealer.key_json(),
            key_a.key_json(),
            key_b.key_json(),
        ],
        vec![json!(seal_a_ref)],
        vec![],
    );
    let rep = verify_bundle_value(&bundle, &opts);

    // Revocation Row 2 (`chain_not_carried` naming `missing_l0_ref`) vs Row 1 (`ok` naming `b_leaf_ref`) vs Row 4 (`chain_not_carried` naming `end_missing_key_ref`)
    let f_rev_root = find_authority_finding(&rep, &rev_by_root_ref).unwrap();
    assert_eq!(
        (&f_rev_root.result[..], &f_rev_root.code[..]),
        ("incomplete", "chain_not_carried")
    );
    assert_eq!(f_rev_root.about.as_deref(), Some(missing_l0_ref.as_str()));

    let f_rev_iss = find_authority_finding(&rep, &rev_by_issuer_ref).unwrap();
    assert_eq!((&f_rev_iss.result[..], &f_rev_iss.code[..]), ("ok", "ok"));
    assert_eq!(f_rev_iss.about.as_deref(), Some(b_leaf_ref.as_str()));

    let f_rev_mk = find_authority_finding(&rep, &rev_mk_target_ref).unwrap();
    assert_eq!(
        (&f_rev_mk.result[..], &f_rev_mk.code[..]),
        ("incomplete", "chain_not_carried")
    );
    assert_eq!(
        f_rev_mk.about.as_deref(),
        Some(end_missing_key_ref.as_str())
    );

    // Link with failed body -> `not_covered`; link with `missing_key` and non-root issuer -> `no_standing`
    assert_eq!(
        find_authority_finding(&rep, &bad_body_end_ref)
            .unwrap()
            .code,
        "not_covered"
    );
    assert_eq!(
        find_authority_finding(&rep, &end_missing_key_ref)
            .unwrap()
            .code,
        "no_standing"
    );

    // Loop with lead-in: `obs_a_early` stands (`ok`), `obs_a_late` is `ended` (`about = s_ab_ref`), `obs_b` has `no_standing`!
    assert_eq!(
        find_authority_finding(&rep, &obs_a_early_ref).unwrap().code,
        "ok"
    );
    let f_a_late = find_authority_finding(&rep, &obs_a_late_ref).unwrap();
    assert_eq!(
        (&f_a_late.result[..], &f_a_late.code[..]),
        ("failed", "ended")
    );
    assert_eq!(f_a_late.about.as_deref(), Some(s_ab_ref.as_str()));
    assert_eq!(
        find_authority_finding(&rep, &obs_b_ref).unwrap().code,
        "no_standing"
    );
}

#[test]
fn a5_definition_published_gets_no_authority_finding_under_trusted_roots_and_unchanged_without_roots()
 {
    let root = TestKey::from_seed(210);
    let worker = TestKey::from_seed(211);
    let publisher = TestKey::from_seed(212);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");

    let (prof_ref, prof_blob) = make_blob(&json!({
        "format": "r5e.capture-profile/v2",
        "schemas": {
            "provenance.r5e.io/v2/DefinitionPublished": def_pub_sref,
            "provenance.r5e.io/v2/Endorsement": end_sref,
            "provenance.r5e.io/v2/Observation": obs_sref,
            "provenance.r5e.io/v2/Revocation": rev_sref
        },
        "authority": {
            "bindings": [{
                "streamPrefix": "stream:s/",
                "actorPrefixes": ["actor:a/"],
                "issuerKeys": [&root.keyid, &worker.keyid, &publisher.keyid],
                "sealerKeys": []
            }],
            "checkpointKeys": []
        },
        "durability": {
            "failureDomain": "node",
            "requiredPayloads": "submitted",
            "onFailure": "refuse"
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": bytes_ref_of(b"policy")
    }));

    let (pub_ref, pub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": prof_ref,
            "issuer": publisher.keyid,
            "actor": "actor:a/publisher",
            "stream": "stream:s/pubs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T09:00:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": def_pub_sref},
                    {"kind": "provenance.r5e.io/v2/Endorsement", "definition": end_sref},
                    {"kind": "provenance.r5e.io/v2/Observation", "definition": obs_sref}
                ]
            }
        }),
        &[&publisher],
    );
    let (end_ref, end_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:a/root",
            "stream": "stream:s/auth",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T09:05:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-11T09:00:00Z",
                "notAfter": "2026-11-11T12:00:00Z"
            }
        }),
        &[&root],
    );
    let (obs_ref, obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:a/worker",
            "stream": "stream:s/work",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T09:10:00Z",
            "body": {"topic": "smoke", "contentRefs": []}
        }),
        &[&worker],
    );

    let bundle = empty_bundle_with(
        vec![pub_rec.clone(), end_rec.clone(), obs_rec.clone()],
        vec![prof_blob.clone()],
        vec![root.key_json(), worker.key_json(), publisher.key_json()],
        vec![],
        vec![],
    );

    // 1. Under `trusted_roots` + trusted publisher: `DefinitionPublished` has NO `authority` finding,
    //    and the entire bundle is established (`failed == 0 && incomplete == 0`).
    let mut opts_est = VerifyOptions::default();
    opts_est.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    opts_est.trusted_publishers = [publisher.keyid.clone()].into_iter().collect();
    let rep_est = verify_bundle_value(&bundle, &opts_est);
    assert!(find_authority_finding(&rep_est, &pub_ref).is_none());
    assert_eq!(
        find_authority_finding(&rep_est, &end_ref).unwrap().code,
        "ok"
    );
    assert_eq!(
        find_authority_finding(&rep_est, &obs_ref).unwrap().code,
        "ok"
    );
    assert!(rep_est.is_established());

    // 2. Under `trusted_roots` with NO trusted publisher: `DefinitionPublished` still gets NO
    //    `authority` finding, nothing fails (`failed == 0`), and `publication` findings are `incomplete`.
    let mut opts_untrusted_pub = VerifyOptions::default();
    opts_untrusted_pub.trusted_roots = Some([root.keyid.clone()].into_iter().collect());
    let rep_untrusted_pub = verify_bundle_value(&bundle, &opts_untrusted_pub);
    assert!(find_authority_finding(&rep_untrusted_pub, &pub_ref).is_none());
    assert_eq!(rep_untrusted_pub.summary.failed, 0);
    assert_eq!(rep_untrusted_pub.summary.incomplete, 3);

    // 3. When `trusted_roots` is `None`, §6.3 applies unchanged (`DefinitionPublished` gets §6.3 `authority`).
    let mut opts_no_roots = VerifyOptions::default();
    opts_no_roots.trusted_profiles = [prof_ref.clone()].into_iter().collect();
    opts_no_roots.trusted_publishers = [publisher.keyid.clone()].into_iter().collect();
    let rep_no_roots = verify_bundle_value(&bundle, &opts_no_roots);
    let f_pub_profile_auth = find_authority_finding(&rep_no_roots, &pub_ref).unwrap();
    assert_eq!(f_pub_profile_auth.result, "ok");
    assert_eq!(f_pub_profile_auth.about.as_deref(), Some(prof_ref.as_str()));
    assert!(rep_no_roots.is_established());

    // 4. A `Revocation` targeting a carried `DefinitionPublished` is `failed` / `not_covered` (`about = null`).
    let (rev_pub_ref, rev_pub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": prof_ref,
            "issuer": publisher.keyid,
            "actor": "actor:a/publisher",
            "stream": "stream:s/pubs-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T09:20:00Z",
            "body": {"target": pub_ref}
        }),
        &[&publisher],
    );
    let bundle_with_rev = empty_bundle_with(
        vec![pub_rec, end_rec, obs_rec, rev_pub_rec],
        vec![prof_blob],
        vec![root.key_json(), worker.key_json(), publisher.key_json()],
        vec![],
        vec![],
    );
    let rep_rev = verify_bundle_value(&bundle_with_rev, &opts_est);
    let f_rev = find_authority_finding(&rep_rev, &rev_pub_ref).unwrap();
    assert_eq!(
        (&f_rev.result[..], &f_rev.code[..]),
        ("failed", "not_covered")
    );
    assert_eq!(f_rev.about, None);
}

#[test]
fn untrusted_definition_published_short_circuits_without_consulting_table() {
    let trusted_pub = TestKey::from_seed(220);
    let stranger_pub = TestKey::from_seed(221);
    let unkeyed_stranger = TestKey::from_seed(222);
    let unkeyed_trusted = TestKey::from_seed(223);
    let worker = TestKey::from_seed(224);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let alt_def_pub_sref = bytes_ref_of(b"alt-definition-published-doc");

    let (prof_ref, prof_blob) = make_profile(
        json!({
            "provenance.r5e.io/v2/DefinitionPublished": def_pub_sref,
            "provenance.r5e.io/v2/Observation": obs_sref,
        }),
        &[
            &trusted_pub.keyid,
            &stranger_pub.keyid,
            &unkeyed_stranger.keyid,
            &unkeyed_trusted.keyid,
            &worker.keyid,
        ],
        &[],
    );

    // 1. Trusted publisher publishes DefinitionPublished + Observation.
    let (trusted_pub_ref, trusted_pub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": prof_ref,
            "issuer": trusted_pub.keyid,
            "actor": "actor:trusted-pub",
            "stream": "stream:pubs-trusted",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T10:00:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": def_pub_sref},
                    {"kind": "provenance.r5e.io/v2/Observation", "definition": obs_sref}
                ]
            }
        }),
        &[&trusted_pub],
    );

    // 2. Stranger publisher restates the same definitions alongside the trusted one.
    let (stranger_same_ref, stranger_same_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": prof_ref,
            "issuer": stranger_pub.keyid,
            "actor": "actor:stranger",
            "stream": "stream:pubs-stranger-same",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T10:01:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": def_pub_sref},
                    {"kind": "provenance.r5e.io/v2/Observation", "definition": obs_sref}
                ]
            }
        }),
        &[&stranger_pub],
    );

    // 3. Stranger publisher with a different `schemaRef` and missing key: because the table is NOT
    //    consulted for an untrusted DefinitionPublished, it still gets `incomplete` /
    //    `publisher_not_trusted` (`about = its own reference`), never `definition_differs_from_published`
    //    or `publication_not_carried`.
    let (stranger_alt_ref, stranger_alt_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": alt_def_pub_sref,
            "profileRef": prof_ref,
            "issuer": unkeyed_stranger.keyid,
            "actor": "actor:unkeyed-stranger",
            "stream": "stream:pubs-stranger-alt",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T10:02:00Z",
            "body": {
                "definitions": []
            }
        }),
        &[&unkeyed_stranger],
    );

    // 4. Ordinary Observation record.
    let (obs_ref, obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": worker.keyid,
            "actor": "actor:worker",
            "stream": "stream:work",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T10:03:00Z",
            "body": {"topic": "check", "contentRefs": []}
        }),
        &[&worker],
    );

    let bundle = empty_bundle_with(
        vec![
            trusted_pub_rec,
            stranger_same_rec,
            stranger_alt_rec,
            obs_rec,
        ],
        vec![prof_blob.clone()],
        vec![
            trusted_pub.key_json(),
            stranger_pub.key_json(),
            worker.key_json(),
        ],
        vec![],
        vec![],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_profiles.insert(prof_ref.clone());
    opts.trusted_publishers.insert(trusted_pub.keyid.clone());
    opts.trusted_publishers
        .insert(unkeyed_trusted.keyid.clone());

    let rep = verify_bundle_value(&bundle, &opts);
    fn find_pub<'a>(
        r: &'a r5e_verify_rs::provenance_v2::Report,
        subj: &str,
    ) -> &'a r5e_verify_rs::provenance_v2::Finding {
        r.findings
            .iter()
            .find(|f| f.layer == 2 && f.subject == subj && f.check == "publication")
            .unwrap()
    }

    let f_trusted = find_pub(&rep, &trusted_pub_ref);
    assert_eq!((&f_trusted.result[..], &f_trusted.code[..]), ("ok", "ok"));
    assert_eq!(f_trusted.about.as_deref(), Some(trusted_pub_ref.as_str()));

    let f_obs = find_pub(&rep, &obs_ref);
    assert_eq!((&f_obs.result[..], &f_obs.code[..]), ("ok", "ok"));
    assert_eq!(f_obs.about.as_deref(), Some(trusted_pub_ref.as_str()));

    let f_stranger_same = find_pub(&rep, &stranger_same_ref);
    assert_eq!(
        (&f_stranger_same.result[..], &f_stranger_same.code[..]),
        ("incomplete", "publisher_not_trusted")
    );
    assert_eq!(
        f_stranger_same.about.as_deref(),
        Some(stranger_same_ref.as_str())
    );

    let f_stranger_alt = find_pub(&rep, &stranger_alt_ref);
    assert_eq!(
        (&f_stranger_alt.result[..], &f_stranger_alt.code[..]),
        ("incomplete", "publisher_not_trusted")
    );
    assert_eq!(
        f_stranger_alt.about.as_deref(),
        Some(stranger_alt_ref.as_str())
    );

    // 5. Contrast: a trusted publisher's DefinitionPublished whose key is missing states nothing,
    //    and DOES consult the table (yielding `publication_not_carried` when alone).
    let (unkeyed_trusted_pub_ref, unkeyed_trusted_pub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": prof_ref,
            "issuer": unkeyed_trusted.keyid,
            "actor": "actor:trusted-unkeyed",
            "stream": "stream:pubs-trusted-unkeyed",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-11T10:04:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": def_pub_sref}
                ]
            }
        }),
        &[&unkeyed_trusted],
    );
    let bundle_unkeyed_trusted = empty_bundle_with(
        vec![unkeyed_trusted_pub_rec],
        vec![prof_blob],
        vec![],
        vec![],
        vec![],
    );
    let rep_unkeyed = verify_bundle_value(&bundle_unkeyed_trusted, &opts);
    let f_unkeyed = find_pub(&rep_unkeyed, &unkeyed_trusted_pub_ref);
    assert_eq!(
        (&f_unkeyed.result[..], &f_unkeyed.code[..]),
        ("incomplete", "publication_not_carried")
    );
    assert_eq!(f_unkeyed.about.as_deref(), Some(def_pub_sref.as_str()));
}

fn make_full_definitions_list() -> Vec<Value> {
    let idx: Value = serde_json::from_slice(include_bytes!(
        "../vendor/provenance-v2/definitions/index.json"
    ))
    .unwrap();
    idx.as_object()
        .unwrap()
        .iter()
        .map(|(k, d)| json!({"kind": k, "definition": d}))
        .collect()
}

fn find_check_finding<'a>(
    rep: &'a r5e_verify_rs::provenance_v2::Report,
    subject: &str,
    check: &str,
) -> Option<&'a r5e_verify_rs::provenance_v2::Finding> {
    rep.findings
        .iter()
        .find(|f| f.layer == 2 && f.subject == subject && f.check == check)
}

#[test]
fn a6_chain_started_publication_all_rows_and_order_independence() {
    let pub_key = TestKey::from_seed(230);
    let other_pub = TestKey::from_seed(231);
    let unkeyed_pub = TestKey::from_seed(232);
    let boot = TestKey::from_seed(233);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"a6-pub-prof");
    let full_defs = make_full_definitions_list();

    // Valid DefinitionPublished by `pub_key`.
    let (valid_p_ref, valid_p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-valid",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );

    // Non-DefinitionPublished record (`Observation`).
    let (not_dp_ref, not_dp_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:not-dp",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:01Z",
            "body": {"topic": "wrong-kind", "contentRefs": []}
        }),
        &[&pub_key],
    );

    // DefinitionPublished with failed `body` (empty `definitions` violates minItems: 1).
    let (bad_body_p_ref, bad_body_p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-bad-body",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:02Z",
            "body": {"definitions": []}
        }),
        &[&pub_key],
    );

    // DefinitionPublished with failed `signature` (forged 64 zero bytes).
    let bad_sig_payload_bytes = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "DefinitionPublished",
        "schemaRef": def_pub_sref,
        "profileRef": dummy_prof_ref,
        "issuer": pub_key.keyid,
        "actor": "actor:pub",
        "stream": "stream:pub-bad-sig",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-12T00:00:03Z",
        "body": {"definitions": full_defs}
    }))
    .unwrap()
    .into_bytes();
    let bad_sig_p_ref = evidence_ref_of(&bad_sig_payload_bytes);
    let bad_sig_p_rec = json!({
        "ref": bad_sig_p_ref,
        "envelope": {
            "payloadType": DSSE_PAYLOAD_TYPE_V2,
            "payload": STANDARD.encode(&bad_sig_payload_bytes),
            "signatures": [{"keyid": pub_key.keyid, "sig": STANDARD.encode([0u8; 64])}]
        }
    });

    // DefinitionPublished with incomplete `signature` (`unkeyed_pub` omitted from `bundle.keys`).
    let (unkeyed_p_ref, unkeyed_p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": unkeyed_pub.keyid,
            "actor": "actor:unkeyed-pub",
            "stream": "stream:pub-unkeyed",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:04Z",
            "body": {"definitions": full_defs}
        }),
        &[&unkeyed_pub],
    );

    // DefinitionPublished omitting `ChainStarted` from its definitions list.
    let defs_without_cs: Vec<Value> = full_defs
        .iter()
        .filter(|d| d["kind"] != "provenance.r5e.io/v2/ChainStarted")
        .cloned()
        .collect();
    let (no_cs_p_ref, no_cs_p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-no-cs",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:05Z",
            "body": {"definitions": defs_without_cs}
        }),
        &[&pub_key],
    );

    let mk_clean_cs = |slug: &str, p_ref: &str, p_pub: &str, defs: Vec<Value>| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "ChainStarted",
                "schemaRef": cs_sref,
                "profileRef": dummy_prof_ref,
                "issuer": boot.keyid,
                "actor": "actor:boot",
                "stream": format!("urn:r5e:stream:{slug}:start"),
                "seq": 1,
                "previous": null,
                "capturedAt": "2026-11-12T00:01:00Z",
                "body": {
                    "deployment": slug,
                    "bootstrap": boot.keyid,
                    "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                    "publication": p_ref,
                    "publisher": p_pub,
                    "definitions": defs
                }
            }),
            &[&boot],
        )
    };

    // Row 1: missing publication record.
    let missing_p_ref = format!("evidence:sha256:{}", "9".repeat(64));
    let (cs_row1_ref, cs_row1_rec) =
        mk_clean_cs("r1", &missing_p_ref, &pub_key.keyid, full_defs.clone());
    // Row 2a: P is not DefinitionPublished.
    let (cs_row2a_ref, cs_row2a_rec) =
        mk_clean_cs("r2a", &not_dp_ref, &pub_key.keyid, full_defs.clone());
    // Row 2b: P's body is failed — placed BEFORE `bad_body_p_rec` in `bundle.records`!
    let (cs_row2b_ref, cs_row2b_rec) =
        mk_clean_cs("r2b", &bad_body_p_ref, &pub_key.keyid, full_defs.clone());
    // Row 2c: P.issuer != P_pub.
    let (cs_row2c_ref, cs_row2c_rec) =
        mk_clean_cs("r2c", &valid_p_ref, &other_pub.keyid, full_defs.clone());
    // Row 2d: P has failed signature.
    let (cs_row2d_ref, cs_row2d_rec) =
        mk_clean_cs("r2d", &bad_sig_p_ref, &pub_key.keyid, full_defs.clone());
    // Row 3: P has incomplete signature (`missing_key`).
    let (cs_row3_ref, cs_row3_rec) =
        mk_clean_cs("r3", &unkeyed_p_ref, &unkeyed_pub.keyid, full_defs.clone());
    // Row 4a: D_list has duplicate kind (distinct definition refs so `unique: true` on the array passes `body`).
    let mut dup_defs = full_defs.clone();
    let first_kind = full_defs[0]["kind"].as_str().unwrap().to_string();
    dup_defs.push(json!({
        "kind": first_kind,
        "definition": bytes_ref_of(b"alternate-definition-for-duplicate-kind-check"),
    }));
    let (cs_row4a_ref, cs_row4a_rec) = mk_clean_cs("r4a", &valid_p_ref, &pub_key.keyid, dup_defs);
    // Row 4b: D_list equals P.body.definitions, but neither maps ChainStarted to own schemaRef!
    let (cs_row4b_ref, cs_row4b_rec) =
        mk_clean_cs("r4b", &no_cs_p_ref, &pub_key.keyid, defs_without_cs);
    // Row 5: P_pub not in trustedPublishers (`other_pub` signs its own valid DP).
    let (untrusted_p_ref, untrusted_p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": other_pub.keyid,
            "actor": "actor:other-pub",
            "stream": "stream:pub-untrusted",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T00:00:06Z",
            "body": {"definitions": full_defs}
        }),
        &[&other_pub],
    );
    let (cs_row5_ref, cs_row5_rec) =
        mk_clean_cs("r5", &untrusted_p_ref, &other_pub.keyid, full_defs.clone());
    // Row 6: ok.
    let (cs_row6_ref, cs_row6_rec) =
        mk_clean_cs("r6", &valid_p_ref, &pub_key.keyid, full_defs.clone());
    // Fallback when ChainStarted's own `body` is failed (`definitions: []`): falls back to §6.2a (`ok` via `valid_p_rec`)!
    let (cs_bad_body_ref, cs_bad_body_rec) =
        mk_clean_cs("rbad", &missing_p_ref, &pub_key.keyid, vec![]);

    let mut opts = VerifyOptions::default();
    opts.trusted_publishers.insert(pub_key.keyid.clone());
    opts.trusted_publishers.insert(unkeyed_pub.keyid.clone());

    // Place all ChainStarted records BEFORE the DefinitionPublished records to verify order independence.
    let bundle = empty_bundle_with(
        vec![
            cs_row1_rec,
            cs_row2a_rec,
            cs_row2b_rec,
            cs_row2c_rec,
            cs_row2d_rec,
            cs_row3_rec,
            cs_row4a_rec,
            cs_row4b_rec,
            cs_row5_rec,
            cs_row6_rec,
            cs_bad_body_rec,
            valid_p_rec,
            not_dp_rec,
            bad_body_p_rec,
            bad_sig_p_rec,
            unkeyed_p_rec,
            no_cs_p_rec,
            untrusted_p_rec,
        ],
        vec![],
        vec![pub_key.key_json(), other_pub.key_json(), boot.key_json()],
        vec![],
        vec![],
    );
    let rep = verify_bundle_value(&bundle, &opts);

    let assert_pub = |subj: &str, res: &str, code: &str, about: &str| {
        let f = find_check_finding(&rep, subj, "publication").unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..], f.about.as_deref()),
            (res, code, Some(about)),
            "subject {subj}"
        );
    };

    assert_pub(
        &cs_row1_ref,
        "incomplete",
        "publication_not_carried",
        &missing_p_ref,
    );
    assert_pub(
        &cs_row2a_ref,
        "failed",
        "cited_publication_mismatch",
        &not_dp_ref,
    );
    assert_pub(
        &cs_row2b_ref,
        "failed",
        "cited_publication_mismatch",
        &bad_body_p_ref,
    );
    assert_pub(
        &cs_row2c_ref,
        "failed",
        "cited_publication_mismatch",
        &valid_p_ref,
    );
    assert_pub(
        &cs_row2d_ref,
        "failed",
        "cited_publication_mismatch",
        &bad_sig_p_ref,
    );
    assert_pub(
        &cs_row3_ref,
        "incomplete",
        "publication_not_verified",
        &unkeyed_p_ref,
    );
    assert_pub(
        &cs_row4a_ref,
        "failed",
        "definitions_differ_from_publication",
        &valid_p_ref,
    );
    assert_pub(
        &cs_row4b_ref,
        "failed",
        "definitions_differ_from_publication",
        &no_cs_p_ref,
    );
    assert_pub(
        &cs_row5_ref,
        "incomplete",
        "publisher_not_trusted",
        &untrusted_p_ref,
    );
    assert_pub(&cs_row6_ref, "ok", "ok", &valid_p_ref);
    // Fallback to §6.2a when ChainStarted.body != ok (`valid_p_rec` published `cs_sref`!):
    assert_pub(&cs_bad_body_ref, "ok", "ok", &valid_p_ref);
}

#[test]
fn a6_start_stream_rows_1_to_10_unpinned_codes_and_stream_matching() {
    let pub_key = TestKey::from_seed(234);
    let boot = TestKey::from_seed(235);
    let root = TestKey::from_seed(236);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"a6-start-prof");
    let full_defs = make_full_definitions_list();

    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_publishers.insert(pub_key.keyid.clone());
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    // 1. Row 2 vs Row 3 on uppercase candidate start stream (`urn:r5e:stream:UPPER:start`):
    //    - `Observation` hits Row 2 (`not_a_start_record`, `about = "provenance.r5e.io/v2/Observation"`).
    //    - `ChainStarted` hits Row 3 (`wrong_start_position`, `about = "seq:1"`).
    let (obs_upper_ref, obs_upper_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:UPPER:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:01:00Z",
            "body": {"topic": "on-upper-start", "contentRefs": []}
        }),
        &[&root],
    );
    let rep_row2 = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), obs_upper_rec],
            vec![],
            vec![pub_key.key_json(), root.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row2 = find_check_finding(&rep_row2, &obs_upper_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row2.result[..],
            &f_row2.code[..],
            f_row2.about.as_deref()
        ),
        (
            "failed",
            "not_a_start_record",
            Some("provenance.r5e.io/v2/Observation")
        )
    );
    assert_eq!(rep_row2.start, None);

    let (cs_upper_ref, cs_upper_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:UPPER:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:01:00Z",
            "body": {
                "deployment": "upper",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let rep_row3 = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_upper_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row3 = find_check_finding(&rep_row3, &cs_upper_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row3.result[..],
            &f_row3.code[..],
            f_row3.about.as_deref()
        ),
        ("failed", "wrong_start_position", Some("seq:1"))
    );

    // 2. Row 5 (`invalid_start_record`): failed `body` (`definitions: []`) and failed `signature` (`bad_signature`).
    let (cs_bad_body_ref, cs_bad_body_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:02:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": []
            }
        }),
        &[&boot],
    );
    let rep_row5a = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_bad_body_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row5a = find_check_finding(&rep_row5a, &cs_bad_body_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row5a.result[..],
            &f_row5a.code[..],
            f_row5a.about.as_deref()
        ),
        ("failed", "invalid_start_record", None)
    );

    // Failed signature on `ChainStarted`:
    let cs_forged_bytes = encode_canonical_json(&json!({
        "apiVersion": "provenance.r5e.io/v2",
        "kind": "ChainStarted",
        "schemaRef": cs_sref,
        "profileRef": dummy_prof_ref,
        "issuer": boot.keyid,
        "actor": "actor:boot",
        "stream": "urn:r5e:stream:acme:start",
        "seq": 1,
        "previous": null,
        "capturedAt": "2026-11-12T01:02:00Z",
        "body": {
            "deployment": "acme",
            "bootstrap": boot.keyid,
            "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
            "publication": p_ref,
            "publisher": pub_key.keyid,
            "definitions": full_defs
        }
    }))
    .unwrap()
    .into_bytes();
    let cs_forged_ref = evidence_ref_of(&cs_forged_bytes);
    let cs_forged_rec = json!({
        "ref": cs_forged_ref,
        "envelope": {
            "payloadType": DSSE_PAYLOAD_TYPE_V2,
            "payload": STANDARD.encode(&cs_forged_bytes),
            "signatures": [{"keyid": boot.keyid, "sig": STANDARD.encode([0u8; 64])}]
        }
    });
    let rep_row5b = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_forged_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row5b = find_check_finding(&rep_row5b, &cs_forged_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row5b.result[..],
            &f_row5b.code[..],
            f_row5b.about.as_deref()
        ),
        ("failed", "invalid_start_record", None)
    );

    // 3. Row 6 (`unverified_start_record`): incomplete `body` (`missing_definition`) and incomplete `signature` (`missing_key`).
    let unknown_cs_sref = bytes_ref_of(b"uninstalled-chain-started-def");
    let (cs_missing_def_ref, cs_missing_def_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": unknown_cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:03:00Z",
            "body": {"deployment": "acme"}
        }),
        &[&boot],
    );
    let rep_row6a = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_missing_def_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row6a = find_check_finding(&rep_row6a, &cs_missing_def_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row6a.result[..],
            &f_row6a.code[..],
            f_row6a.about.as_deref()
        ),
        ("incomplete", "unverified_start_record", None)
    );

    // `Deployment` with missing second key (`root` omitted from `bundle.keys`):
    // `ChainStarted` at seq 1 is `ok`, `Deployment` at seq 2 hits Row 6 (`unverified_start_record`, `about = null`),
    // and top-level `start` has `chain: null, headSeq: 1`!
    let (cs_ok_ref, cs_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:03:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let (dep_ok_ref, dep_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_ok_ref,
            "capturedAt": "2026-11-12T01:04:00Z",
            "body": {
                "accepts": cs_ok_ref,
                "bootstrap": boot.keyid,
                "claimedBy": root.keyid,
                "roots": [{
                    "key": root.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root.pk)}
                }],
                "threshold": 1
            }
        }),
        &[&boot, &root],
    );
    let rep_row6b = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_ok_rec.clone(), dep_ok_rec.clone()],
            vec![],
            vec![pub_key.key_json(), boot.key_json()], // `root` omitted!
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row6b = find_check_finding(&rep_row6b, &dep_ok_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row6b.result[..],
            &f_row6b.code[..],
            f_row6b.about.as_deref()
        ),
        ("incomplete", "unverified_start_record", None)
    );
    let st_6b = rep_row6b.start.as_ref().unwrap();
    assert_eq!(st_6b.chain, None);
    assert_eq!(st_6b.head_seq, 1);
    assert_eq!(st_6b.head_ref, cs_ok_ref);

    // 4. Row 7 (`deployment_stream_mismatch`): `R.stream != "urn:r5e:stream:" + R.body.deployment + ":start"`.
    let (cs_mismatch_ref, cs_mismatch_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:wrong-slug:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:05:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let rep_row7 = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_mismatch_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row7 = find_check_finding(&rep_row7, &cs_mismatch_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row7.result[..],
            &f_row7.code[..],
            f_row7.about.as_deref()
        ),
        (
            "failed",
            "deployment_stream_mismatch",
            Some("urn:r5e:stream:wrong-slug:start")
        )
    );

    // 5. Row 8 (`invalid_start_record` from duplicate `kind` in `ChainStarted.body.definitions`):
    let mut dup_defs = full_defs.clone();
    dup_defs.push(full_defs[0].clone());
    let (cs_dup_kind_ref, cs_dup_kind_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T01:06:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": dup_defs
            }
        }),
        &[&boot],
    );
    let rep_row8 = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec, cs_dup_kind_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json()],
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_row8 = find_check_finding(&rep_row8, &cs_dup_kind_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row8.result[..],
            &f_row8.code[..],
            f_row8.about.as_deref()
        ),
        ("failed", "invalid_start_record", None)
    );
}

#[test]
fn a6_deployment_rows_11_to_19_fork_tiebreak_and_a5_feeding() {
    let pub_key = TestKey::from_seed(240);
    let boot = TestKey::from_seed(241);
    let boot2 = TestKey::from_seed(242);
    let root1 = TestKey::from_seed(243);
    let root2 = TestKey::from_seed(244);
    let recov = TestKey::from_seed(245);
    let cust1 = TestKey::from_seed(246);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let princ_sref = base_schema_ref("provenance.r5e.io/v2/Principal");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"a6-dep-prof");
    let full_defs = make_full_definitions_list();

    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );

    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:01:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );

    // 1. Row 11 (`invalid_deployment_terms`): check duplicate roots, claimedBy not in roots,
    //    duplicate recoveryKeys, duplicate custodian identity, duplicate custodian key,
    //    and confirm multiple keyless custodians succeed!
    let bad_term_bodies = vec![
        // Duplicate root key (distinct root objects so `unique: true` passes `body`):
        json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": root1.keyid,
            "roots": [
                {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}},
                {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}, "holder": "operator"}
            ],
            "threshold": 1
        }),
        // claimedBy not in roots:
        json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": root1.keyid,
            "roots": [
                {"key": root2.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root2.pk)}}
            ],
            "threshold": 1
        }),
        // recoveryKeys overlapping roots (`unique: true` rejects identical strings in `body`, so test overlap here):
        json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": root1.keyid,
            "roots": [
                {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
            ],
            "recoveryKeys": [root1.keyid],
            "threshold": 1
        }),
        // Duplicate custodian identity (distinct objects so `unique: true` passes `body`):
        json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": root1.keyid,
            "roots": [
                {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
            ],
            "custodians": [
                {"identity": "mailto:alice@example.com"},
                {"identity": "mailto:alice@example.com", "key": cust1.keyid}
            ],
            "threshold": 1
        }),
        // Duplicate custodian key:
        json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": root1.keyid,
            "roots": [
                {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
            ],
            "custodians": [
                {"identity": "mailto:alice@example.com", "key": cust1.keyid},
                {"identity": "mailto:bob@example.com", "key": cust1.keyid}
            ],
            "threshold": 1
        }),
    ];

    let mut root_opts = VerifyOptions::default();
    root_opts.trusted_publishers.insert(pub_key.keyid.clone());
    root_opts.trusted_roots = Some([root1.keyid.clone()].into_iter().collect());

    for bad_body in bad_term_bodies {
        let (d_ref, d_rec) = make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Deployment",
                "schemaRef": dep_sref,
                "profileRef": dummy_prof_ref,
                "issuer": boot.keyid,
                "actor": "actor:boot",
                "stream": "urn:r5e:stream:acme:start",
                "seq": 2,
                "previous": cs_ref,
                "capturedAt": "2026-11-12T02:02:00Z",
                "body": bad_body
            }),
            &[&boot, &root1],
        );
        let rep = verify_bundle_value(
            &empty_bundle_with(
                vec![p_rec.clone(), cs_rec.clone(), d_rec],
                vec![],
                vec![pub_key.key_json(), boot.key_json(), root1.key_json()],
                vec![],
                vec![],
            ),
            &root_opts,
        );
        let f = find_check_finding(&rep, &d_ref, "start").unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..], f.about.as_deref()),
            ("failed", "invalid_deployment_terms", None)
        );
    }

    // 2. Valid multi-root + multiple keyless custodians Deployment under `trustedChain`:
    //    Verify `root2` (second root, not `claimedBy`) gets `authority: ok`, while `boot` gets `no_standing`,
    //    and `Principal`, `DefinitionPublished`, `ChainStarted`, `Deployment` get NO `authority` finding!
    let (valid_dep_ref, valid_dep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T02:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": root1.keyid,
                "roots": [
                    {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}},
                    {"key": root2.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root2.pk)}}
                ],
                "recoveryKeys": [recov.keyid],
                "custodians": [
                    {"identity": "mailto:alice@example.com"},
                    {"identity": "mailto:bob@example.com"},
                    {"identity": "mailto:carol@example.com", "key": cust1.keyid}
                ],
                "threshold": 2
            }
        }),
        &[&boot, &root1],
    );
    let (princ_ref, princ_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Principal",
            "schemaRef": princ_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root1.keyid,
            "actor": "actor:root1",
            "stream": "stream:princ",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:03:00Z",
            "body": {
                "key": root2.keyid,
                "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root2.pk)},
                "holder": "root2"
            }
        }),
        &[&root1],
    );
    let (end_root2_ref, end_root2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root2.keyid,
            "actor": "actor:root2",
            "stream": "stream:end-r2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:03:30Z",
            "body": {
                "subject": cust1.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T02:00:00Z",
                "notAfter": "2026-11-12T03:00:00Z"
            }
        }),
        &[&root2],
    );
    let (obs_cust1_ref, obs_cust1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": cust1.keyid,
            "actor": "actor:cust1",
            "stream": "stream:obs-c1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:04:00Z",
            "body": {"topic": "via-second-root-endorsement", "contentRefs": []}
        }),
        &[&cust1],
    );
    let (obs_root2_ref, obs_root2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root2.keyid,
            "actor": "actor:root2",
            "stream": "stream:obs-r2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:04:00Z",
            "body": {"topic": "by-second-root-without-grant", "contentRefs": []}
        }),
        &[&root2],
    );
    let (obs_boot_ref, obs_boot_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "stream:obs-boot",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:05:00Z",
            "body": {"topic": "by-bootstrap-after-start", "contentRefs": []}
        }),
        &[&boot],
    );

    let mut chain_opts = VerifyOptions::default();
    chain_opts.trusted_publishers.insert(pub_key.keyid.clone());
    chain_opts.trusted_chain = Some(valid_dep_ref.clone());

    let rep_est = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                valid_dep_rec.clone(),
                princ_rec.clone(),
                end_root2_rec,
                obs_cust1_rec,
                obs_root2_rec.clone(),
                obs_boot_rec,
            ],
            vec![],
            vec![
                pub_key.key_json(),
                boot.key_json(),
                root1.key_json(),
                root2.key_json(),
                cust1.key_json(),
            ],
            vec![],
            vec![],
        ),
        &chain_opts,
    );
    assert!(find_authority_finding(&rep_est, &p_ref).is_none());
    assert!(find_authority_finding(&rep_est, &princ_ref).is_none());
    assert!(find_authority_finding(&rep_est, &cs_ref).is_none());
    assert!(find_authority_finding(&rep_est, &valid_dep_ref).is_none());
    let f_end_auth = find_authority_finding(&rep_est, &end_root2_ref).unwrap();
    assert_eq!(
        (
            &f_end_auth.result[..],
            &f_end_auth.code[..],
            f_end_auth.about.as_deref()
        ),
        ("ok", "ok", Some(root2.keyid.as_str()))
    );
    let f_c1_auth = find_authority_finding(&rep_est, &obs_cust1_ref).unwrap();
    assert_eq!(
        (
            &f_c1_auth.result[..],
            &f_c1_auth.code[..],
            f_c1_auth.about.as_deref()
        ),
        ("ok", "ok", Some(end_root2_ref.as_str()))
    );
    let f_r2_auth = find_authority_finding(&rep_est, &obs_root2_ref).unwrap();
    assert_eq!(
        (&f_r2_auth.result[..], &f_r2_auth.code[..]),
        ("failed", "not_covered")
    );
    let f_boot_auth = find_authority_finding(&rep_est, &obs_boot_ref).unwrap();
    assert_eq!(
        (&f_boot_auth.result[..], &f_boot_auth.code[..]),
        ("failed", "no_standing")
    );

    // 3. Row 16 (`unverified_start_record` with `about = C.ref`) & Row 15 preceding Row 16 when `C` is incomplete (`missing_key`):
    //    - When `boot` is omitted from `bundle.keys` (using a `Deployment` signed by `[&boot2, &root1]` vs `[&boot, &root1]`):
    //      For `valid_dep_rec` (signed by `boot` + `root1`), omitting `boot` makes `Deployment` itself hit Row 6.
    //      Instead, omit a definition or test `Deployment` signed by `boot2` (`bootstrap_signer_mismatch`) when `cs_rec` (`boot`) has `missing_key`!
    let (dep_boot2_ref, dep_boot2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot2.keyid,
            "actor": "actor:boot2",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T02:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot2.keyid,
                "claimedBy": root1.keyid,
                "roots": [
                    {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
                ],
                "threshold": 1
            }
        }),
        &[&boot2, &root1],
    );
    let rep_row15_incomplete_c = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_rec.clone(), dep_boot2_rec],
            vec![],
            vec![pub_key.key_json(), boot2.key_json(), root1.key_json()], // `boot` missing so `cs_rec.start == incomplete`!
            vec![],
            vec![],
        ),
        &root_opts,
    );
    let f_cs_inc = find_check_finding(&rep_row15_incomplete_c, &cs_ref, "start").unwrap();
    assert_eq!(
        (&f_cs_inc.result[..], &f_cs_inc.code[..]),
        ("incomplete", "unverified_start_record")
    );
    let f_dep_r15 = find_check_finding(&rep_row15_incomplete_c, &dep_boot2_ref, "start").unwrap();
    assert_eq!(
        (
            &f_dep_r15.result[..],
            &f_dep_r15.code[..],
            f_dep_r15.about.as_deref()
        ),
        (
            "failed",
            "bootstrap_signer_mismatch",
            Some(boot.keyid.as_str())
        )
    );

    // Row 16 (`C.start == incomplete` while `Deployment`'s own body + sigs are `ok`):
    // Give `ChainStarted` an uncarried `schemaRef` (`definition_not_available` -> `C.body == incomplete` -> `C.start == incomplete`),
    // while `boot` and `root1` ARE in `bundle.keys` and `Deployment` uses the bundled `Deployment` schemaRef!
    let uncarried_cs_sref = bytes_ref_of(b"uncarried-chain-started-def");
    let (cs_unverified_ref, cs_unverified_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": uncarried_cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:01:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let (dep_on_unverified_ref, dep_on_unverified_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_unverified_ref,
            "capturedAt": "2026-11-12T02:02:00Z",
            "body": {
                "accepts": cs_unverified_ref,
                "bootstrap": boot.keyid,
                "claimedBy": root1.keyid,
                "roots": [
                    {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
                ],
                "threshold": 1
            }
        }),
        &[&boot, &root1],
    );
    let mut row16_opts = VerifyOptions::default();
    row16_opts.trusted_publishers.insert(pub_key.keyid.clone());
    row16_opts.trusted_chain = Some(dep_on_unverified_ref.clone());
    let rep_row16 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_unverified_rec,
                dep_on_unverified_rec,
                obs_root2_rec.clone(),
            ],
            vec![],
            vec![
                pub_key.key_json(),
                boot.key_json(),
                root1.key_json(),
                root2.key_json(),
            ],
            vec![],
            vec![],
        ),
        &row16_opts,
    );
    let f_row16 = find_check_finding(&rep_row16, &dep_on_unverified_ref, "start").unwrap();
    assert_eq!(
        (
            &f_row16.result[..],
            &f_row16.code[..],
            f_row16.about.as_deref()
        ),
        (
            "incomplete",
            "unverified_start_record",
            Some(cs_unverified_ref.as_str())
        )
    );
    // And under `trustedChain`, incomplete start emits `authority: incomplete / chain_not_carried`!
    let f_obs_inc = find_authority_finding(&rep_row16, &obs_root2_ref).unwrap();
    assert_eq!(
        (
            &f_obs_inc.result[..],
            &f_obs_inc.code[..],
            f_obs_inc.about.as_deref()
        ),
        (
            "incomplete",
            "chain_not_carried",
            Some(dep_on_unverified_ref.as_str())
        )
    );

    // 4. Forked `(R.stream, seq = 1)` tie-break (`A6` §4.2 line 289):
    //    - When `R.body.accepts` matches one of the two forked seq=1 records, `about` equals `R.body.accepts`.
    //    - When `R.body.accepts` matches neither, `about` equals the lowest `ref` in byte order.
    let (cs_alt_ref, cs_alt_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T02:01:30Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let higher_cs_ref = std::cmp::max(&cs_ref, &cs_alt_ref).clone();
    let lower_cs_ref = std::cmp::min(&cs_ref, &cs_alt_ref).clone();
    let (dep_accepts_higher_ref, dep_accepts_higher_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": higher_cs_ref,
            "capturedAt": "2026-11-12T02:02:00Z",
            "body": {
                "accepts": higher_cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": root1.keyid,
                "roots": [
                    {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
                ],
                "threshold": 1
            }
        }),
        &[&boot, &root1],
    );
    let rep_fork_match = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                cs_alt_rec.clone(),
                dep_accepts_higher_rec,
            ],
            vec![],
            vec![pub_key.key_json(), boot.key_json(), root1.key_json()],
            vec![],
            vec![],
        ),
        &root_opts,
    );
    let f_fork_match =
        find_check_finding(&rep_fork_match, &dep_accepts_higher_ref, "start").unwrap();
    assert_eq!(
        (
            &f_fork_match.result[..],
            &f_fork_match.code[..],
            f_fork_match.about.as_deref()
        ),
        (
            "failed",
            "accepts_is_not_chain_started",
            Some(higher_cs_ref.as_str())
        )
    );

    let unrelated_accepts = format!("evidence:sha256:{}", "f".repeat(64));
    let (dep_accepts_none_ref, dep_accepts_none_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": unrelated_accepts,
            "capturedAt": "2026-11-12T02:02:00Z",
            "body": {
                "accepts": unrelated_accepts,
                "bootstrap": boot.keyid,
                "claimedBy": root1.keyid,
                "roots": [
                    {"key": root1.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root1.pk)}}
                ],
                "threshold": 1
            }
        }),
        &[&boot, &root1],
    );
    let rep_fork_lowest = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec, cs_rec, cs_alt_rec, dep_accepts_none_rec],
            vec![],
            vec![pub_key.key_json(), boot.key_json(), root1.key_json()],
            vec![],
            vec![],
        ),
        &root_opts,
    );
    let f_fork_lowest =
        find_check_finding(&rep_fork_lowest, &dep_accepts_none_ref, "start").unwrap();
    assert_eq!(
        (
            &f_fork_lowest.result[..],
            &f_fork_lowest.code[..],
            f_fork_lowest.about.as_deref()
        ),
        (
            "failed",
            "accepts_is_not_chain_started",
            Some(lower_cs_ref.as_str())
        )
    );

    // 5. `minStartSeq` on a bundle with NO candidate start stream uses `subject = "bundle"`.
    let mut min_opts = VerifyOptions::default();
    min_opts.min_start_seq = Some(2);
    let rep_empty_min = verify_bundle_value(
        &empty_bundle_with(
            vec![princ_rec],
            vec![],
            vec![root1.key_json()],
            vec![],
            vec![],
        ),
        &min_opts,
    );
    let f_bundle_min = find_check_finding(&rep_empty_min, "bundle", "start").unwrap();
    assert_eq!(
        (
            &f_bundle_min.result[..],
            &f_bundle_min.code[..],
            f_bundle_min.about.as_deref()
        ),
        ("incomplete", "start_below_minimum_position", Some("seq:2"))
    );
}

#[test]
fn a6_cli_and_wasm_options_validation_and_canonical_start_output() {
    let pinned_dir = vectors_cases_dir().join("start-accepted-under-a-pinned-chain");
    let pinned_meta: Value =
        serde_json::from_slice(&fs::read(pinned_dir.join("case.json")).unwrap()).unwrap();
    let pinned_bundle_path = pinned_dir.join("bundle.json");
    let pinned_bundle_bytes = fs::read(&pinned_bundle_path).unwrap();
    let pinned_expected: Value =
        serde_json::from_slice(&fs::read(pinned_dir.join("expected-report.json")).unwrap())
            .unwrap();
    let pinned_expected_canonical = encode_canonical_json(&pinned_expected).unwrap();

    let trusted_profile = pinned_meta["trustedProfiles"][0].as_str().unwrap();
    let trusted_publisher = pinned_meta["trustedPublishers"][0].as_str().unwrap();
    let trusted_chain = pinned_meta["trustedChain"].as_str().unwrap();

    // 1. Library `VerifyOptions::validate` & `verify_bundle_bytes` errors:
    let mut bad_mutual = VerifyOptions::default();
    bad_mutual.trusted_roots = Some(std::collections::BTreeSet::new());
    bad_mutual.trusted_chain = Some(trusted_chain.to_string());
    assert!(verify_bundle_bytes(&pinned_bundle_bytes, &bad_mutual).is_err());

    let mut bad_chain_fmt = VerifyOptions::default();
    bad_chain_fmt.trusted_chain = Some(
        "bytes:sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
    );
    assert!(verify_bundle_bytes(&pinned_bundle_bytes, &bad_chain_fmt).is_err());

    for bad_seq in [
        0u64,
        1u64,
        (r5e_verify_rs::provenance_v2::canonical::MAX_SAFE_INT as u64) + 1,
    ] {
        let mut bad_ms = VerifyOptions::default();
        bad_ms.min_start_seq = Some(bad_seq);
        assert!(verify_bundle_bytes(&pinned_bundle_bytes, &bad_ms).is_err());
    }

    // 2. CLI `--trusted-chain` and `--chain` alias succeed (`exit 0`) and emit canonical JSON with `"start"`:
    for chain_flag in ["--trusted-chain", "--chain"] {
        let out = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
            .arg(&pinned_bundle_path)
            .args(["--trusted-profile", trusted_profile])
            .args(["--trusted-publisher", trusted_publisher])
            .args([chain_flag, trusted_chain])
            .args(["--min-start-seq", "2"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        let stdout_trimmed = std::str::from_utf8(&out.stdout)
            .unwrap()
            .trim_end_matches('\n');
        assert_eq!(stdout_trimmed, pinned_expected_canonical);
    }

    // CLI `--min-start-seq 3` yields `exit 3` (`start_below_minimum_position`), and `exit 0` with `--allow-incomplete`:
    let out_min3 = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
        .arg(&pinned_bundle_path)
        .args(["--trusted-profile", trusted_profile])
        .args(["--trusted-publisher", trusted_publisher])
        .args(["--trusted-chain", trusted_chain])
        .args(["--min-start-seq", "3"])
        .output()
        .unwrap();
    assert_eq!(out_min3.status.code(), Some(3));

    // CLI `--root` alias works identically to `--trusted-root`:
    let root_dir = vectors_cases_dir().join("start-accepted-under-a-trusted-root");
    let root_meta: Value =
        serde_json::from_slice(&fs::read(root_dir.join("case.json")).unwrap()).unwrap();
    let root_expected: Value =
        serde_json::from_slice(&fs::read(root_dir.join("expected-report.json")).unwrap()).unwrap();
    let out_root_alias = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
        .arg(root_dir.join("bundle.json"))
        .args([
            "--trusted-profile",
            root_meta["trustedProfiles"][0].as_str().unwrap(),
        ])
        .args([
            "--trusted-publisher",
            root_meta["trustedPublishers"][0].as_str().unwrap(),
        ])
        .args(["--root", root_meta["trustedRoots"][0].as_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out_root_alias.status.code(), Some(0));
    let root_cli_rep: Value = serde_json::from_slice(&out_root_alias.stdout).unwrap();
    assert_eq!(root_cli_rep, root_expected);

    // 3. CLI mutual exclusion & invalid option values MUST exit `2`:
    let dummy_keyid = format!("key:ed25519:sha256:{}", "a".repeat(64));
    let invalid_cli_arg_sets: Vec<Vec<&str>> = vec![
        vec![
            "--trusted-root",
            &dummy_keyid,
            "--trusted-chain",
            trusted_chain,
        ],
        vec!["--root", &dummy_keyid, "--chain", trusted_chain],
        vec!["--establish-authority", "--trusted-chain", trusted_chain],
        vec!["--trusted-chain", "not-an-evidence-ref"],
        vec!["--trusted-chain", trusted_chain, "--chain", trusted_chain],
        vec!["--min-start-seq", "1"],
        vec!["--min-start-seq", "0"],
        vec!["--min-start-seq", "-2"],
        vec!["--min-start-seq", "two"],
        vec!["--min-start-seq", "2", "--min-start-seq", "3"],
    ];
    for extra_args in invalid_cli_arg_sets {
        let out_err = Command::new(env!("CARGO_BIN_EXE_recurse_verify"))
            .arg(&pinned_bundle_path)
            .args(&extra_args)
            .output()
            .unwrap();
        assert_eq!(
            out_err.status.code(),
            Some(2),
            "expected exit 2 for args {extra_args:?}"
        );
        assert!(out_err.stdout.is_empty());
    }

    // 4. WASM JSON FFI (`verify_v2_ffi_bytes`):
    let wasm_ok: Value = serde_json::from_slice(&r5e_verify_rs::verify_v2_ffi_bytes(
        &pinned_bundle_bytes,
        &serde_json::to_vec(&json!({
            "trustedProfiles": [trusted_profile],
            "trustedPublishers": [trusted_publisher],
            "trustedRoots": null,
            "trustedChain": trusted_chain,
            "minStartSeq": 2
        }))
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(wasm_ok["ok"], true);
    assert_eq!(wasm_ok["sound"], true);
    assert_eq!(wasm_ok["established"], true);
    assert_eq!(wasm_ok["exitCode"], 0);
    assert_eq!(wasm_ok["report"], pinned_expected);
    assert_eq!(
        wasm_ok["canonicalReportJson"].as_str().unwrap(),
        pinned_expected_canonical
    );

    for bad_wasm_opts in [
        json!({"trustedRoots": [], "trustedChain": trusted_chain}),
        json!({"trustedRoots": [dummy_keyid], "trustedChain": trusted_chain}),
        json!({"trustedChain": "evidence:sha256:UPPERCASE"}),
        json!({"minStartSeq": 1}),
        json!({"minStartSeq": 0}),
        json!({"minStartSeq": -5}),
        json!({"minStartSeq": 2.5}),
    ] {
        let wasm_err: Value = serde_json::from_slice(&r5e_verify_rs::verify_v2_ffi_bytes(
            &pinned_bundle_bytes,
            &serde_json::to_vec(&bad_wasm_opts).unwrap(),
        ))
        .unwrap();
        assert_eq!(wasm_err["ok"], false, "expected error for {bad_wasm_opts}");
        assert_eq!(
            wasm_err["exitCode"], 2,
            "expected exitCode 2 for {bad_wasm_opts}"
        );
    }
}

#[test]
fn a6_slice2_terms_and_roots_changed_all_rows_and_spent_recovery_keys() {
    let pub_key = TestKey::from_seed(180);
    let boot = TestKey::from_seed(181);
    let r1 = TestKey::from_seed(182);
    let r2 = TestKey::from_seed(183);
    let r3 = TestKey::from_seed(184);
    let rec_k1 = TestKey::from_seed(185);
    let rec_k2 = TestKey::from_seed(186);
    let cust_k1 = TestKey::from_seed(187);
    let cust_k2 = TestKey::from_seed(188);
    let stranger = TestKey::from_seed(189);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let rc_sref = base_schema_ref("provenance.r5e.io/v2/RootsChanged");
    let rca_sref = base_schema_ref("provenance.r5e.io/v2/RootChangeApproval");
    let dummy_prof_ref = bytes_ref_of(b"a6-s2-prof");
    let full_defs = make_full_definitions_list();

    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-s2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );

    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:01:00Z",
            "body": {
                "deployment": "acme",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );

    let root_entry = |k: &TestKey| {
        json!({
            "key": k.keyid,
            "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(k.pk)}
        })
    };

    let all_keys = vec![
        pub_key.key_json(),
        boot.key_json(),
        r1.key_json(),
        r2.key_json(),
        r3.key_json(),
        rec_k1.key_json(),
        rec_k2.key_json(),
        cust_k1.key_json(),
        cust_k2.key_json(),
        stranger.key_json(),
    ];

    // 1. Tightened terms (§3.2 clauses 5 & 6) on Deployment:
    // Clause 5a: custodian key overlaps `roots[*].key`
    // Clause 5b: custodian key overlaps `recoveryKeys`
    // Clause 6: `roots[*].holder == "agent"`
    for (bad_roots, bad_rk, bad_cust) in [
        (
            vec![root_entry(&r1)],
            vec![rec_k1.keyid.clone()],
            json!([{"identity": "mailto:alice@example.com", "key": r1.keyid}]),
        ),
        (
            vec![root_entry(&r1)],
            vec![rec_k1.keyid.clone()],
            json!([{"identity": "mailto:alice@example.com", "key": rec_k1.keyid}]),
        ),
        (
            vec![json!({
                "key": r1.keyid,
                "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)},
                "holder": "agent"
            })],
            vec![],
            json!([]),
        ),
    ] {
        let mut dep_body = json!({
            "accepts": cs_ref,
            "bootstrap": boot.keyid,
            "claimedBy": r1.keyid,
            "roots": bad_roots,
            "threshold": 1
        });
        if !bad_rk.is_empty() {
            dep_body["recoveryKeys"] = json!(bad_rk);
        }
        if !bad_cust.as_array().unwrap().is_empty() {
            dep_body["custodians"] = bad_cust;
        }
        let (bad_dep_ref, bad_dep_rec) = make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Deployment",
                "schemaRef": dep_sref,
                "profileRef": dummy_prof_ref,
                "issuer": boot.keyid,
                "actor": "actor:boot",
                "stream": "urn:r5e:stream:acme:start",
                "seq": 2,
                "previous": cs_ref,
                "capturedAt": "2026-11-12T10:02:00Z",
                "body": dep_body
            }),
            &[&boot, &r1],
        );
        let mut opts = VerifyOptions::default();
        opts.trusted_publishers.insert(pub_key.keyid.clone());
        opts.trusted_chain = Some(bad_dep_ref.clone());
        let rep = verify_bundle_value(
            &empty_bundle_with(
                vec![p_rec.clone(), cs_rec.clone(), bad_dep_rec],
                vec![],
                all_keys.clone(),
                vec![],
                vec![],
            ),
            &opts,
        );
        let f = find_check_finding(&rep, &bad_dep_ref, "start").unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..], f.about.as_deref()),
            ("failed", "invalid_deployment_terms", None)
        );
    }

    // Valid Deployment at seq = 2 (`threshold: 2`, roots `[r1, r2]`, recoveryKeys `[rec_k1, rec_k2]`,
    // custodians `[alice -> cust_k1, bob -> cust_k2]`).
    let (dep_ref, dep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T10:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": r1.keyid,
                "roots": [root_entry(&r1), root_entry(&r2)],
                "threshold": 2,
                "recoveryKeys": [rec_k1.keyid, rec_k2.keyid],
                "custodians": [
                    {"identity": "mailto:alice@example.com", "key": cust_k1.keyid},
                    {"identity": "mailto:bob@example.com", "key": cust_k2.keyid}
                ]
            }
        }),
        &[&boot, &r1],
    );

    let mut base_opts = VerifyOptions::default();
    base_opts.trusted_publishers.insert(pub_key.keyid.clone());
    base_opts.trusted_chain = Some(dep_ref.clone());

    // 2. Row 3: RootsChanged at seq = 2 -> `wrong_start_position` (`seq:2`).
    let (rc_seq2_ref, rc_seq2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": cs_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    let rep_seq2 = verify_bundle_value(
        &empty_bundle_with(
            vec![p_rec.clone(), cs_rec.clone(), rc_seq2_rec],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &base_opts,
    );
    let f_seq2 = find_check_finding(&rep_seq2, &rc_seq2_ref, "start").unwrap();
    assert_eq!(
        (
            &f_seq2.result[..],
            &f_seq2.code[..],
            f_seq2.about.as_deref()
        ),
        ("failed", "wrong_start_position", Some("seq:2"))
    );

    // 3. Row 20 (`invalid_deployment_terms` via `holder == "agent"` on RootsChanged),
    //    Row 21 (`R.previous != replaces` -> `replaces_is_not_prior_start`),
    //    Row 22 (`prior_start_not_carried` at seq = 4 when seq = 3 is omitted),
    //    Row 23 (`P.ref != replaces` -> `replaces_is_not_prior_start`),
    //    Row 24 (`start_chain_mismatch` at n = 3 and n = 4),
    //    Row 25 (`start_timestamp_regression`),
    //    Row 27 (`unauthorized_recovery_signer`),
    //    Row 29 (`proposer_not_a_root`).
    let other_ref = evidence_ref_of(b"some-other-ref");

    // Row 20
    let (rc_r20_ref, rc_r20_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [{
                    "key": r3.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r3.pk)},
                    "holder": "agent"
                }],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 21 (`previous != replaces`)
    let (rc_r21_ref, rc_r21_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": other_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 22 (`seq = 4` with `seq = 3` omitted)
    let (rc_r22_ref, rc_r22_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 4,
            "previous": other_ref,
            "capturedAt": "2026-11-12T10:04:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": other_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 23 (`P.ref != replaces` while `previous == replaces`)
    let (rc_r23_ref, rc_r23_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": other_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": other_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 24 (`chain != D_ref` at n = 3)
    let (rc_r24_ref, rc_r24_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": other_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 25 (`capturedAt < P.capturedAt`)
    let (rc_r25_ref, rc_r25_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:01:30Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&rec_k1],
    );
    // Row 27 (`unauthorized_recovery_signer`)
    let (rc_r27_ref, rc_r27_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": stranger.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(stranger.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&stranger],
    );
    // Row 29 (`proposer_not_a_root`)
    let (rc_r29_ref, rc_r29_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:03:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "quorum",
                "signer": stranger.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(stranger.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&stranger],
    );

    for (rc_ref, rc_rec, exp_res, exp_code, exp_about) in [
        (
            &rc_r20_ref,
            rc_r20_rec,
            "failed",
            "invalid_deployment_terms",
            None,
        ),
        (
            &rc_r21_ref,
            rc_r21_rec,
            "failed",
            "replaces_is_not_prior_start",
            Some(dep_ref.as_str()),
        ),
        (
            &rc_r22_ref,
            rc_r22_rec,
            "incomplete",
            "prior_start_not_carried",
            Some(other_ref.as_str()),
        ),
        (
            &rc_r23_ref,
            rc_r23_rec,
            "failed",
            "replaces_is_not_prior_start",
            Some(dep_ref.as_str()),
        ),
        (
            &rc_r24_ref,
            rc_r24_rec,
            "failed",
            "start_chain_mismatch",
            Some(dep_ref.as_str()),
        ),
        (
            &rc_r25_ref,
            rc_r25_rec,
            "failed",
            "start_timestamp_regression",
            Some(dep_ref.as_str()),
        ),
        (
            &rc_r27_ref,
            rc_r27_rec,
            "failed",
            "unauthorized_recovery_signer",
            Some(stranger.keyid.as_str()),
        ),
        (
            &rc_r29_ref,
            rc_r29_rec,
            "failed",
            "proposer_not_a_root",
            Some(stranger.keyid.as_str()),
        ),
    ] {
        let rep = verify_bundle_value(
            &empty_bundle_with(
                vec![p_rec.clone(), cs_rec.clone(), dep_rec.clone(), rc_rec],
                vec![],
                all_keys.clone(),
                vec![],
                vec![],
            ),
            &base_opts,
        );
        let f = find_check_finding(&rep, rc_ref, "start").unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..], f.about.as_deref()),
            (exp_res, exp_code, exp_about),
            "unexpected start finding for {exp_code}"
        );
    }

    // 4. Cumulative `spent_recovery_keys` across seq = 3 -> seq = 4 (Row 28) AND Row 30 (`quorum_not_configured`):
    // At seq = 3, `rec_k1` validly recovers to `[r3]` with `recoveryKeys: [rec_k2]` (and NO `custodians`!).
    // Then at seq = 4:
    //  (a) `rec_k2` recovers but tries to put `rec_k1` (spent at seq = 3!) back into `recoveryKeys` -> `spent_recovery_key_retained` (`about = rec_k1.keyid`)!
    //  (b) `r3` proposes a `quorum` change at seq = 4 when seq = 3 omitted `custodians` -> `quorum_not_configured` (`about = None`)!
    let (rc3_ok_ref, rc3_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k1.keyid,
            "actor": "actor:rec1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:05:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1,
                "recoveryKeys": [rec_k2.keyid]
            }
        }),
        &[&rec_k1],
    );
    let (rc4_spent_ref, rc4_spent_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k2.keyid,
            "actor": "actor:rec2",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 4,
            "previous": rc3_ok_ref,
            "capturedAt": "2026-11-12T10:06:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": rc3_ok_ref,
                "authorization": "recovery",
                "signer": rec_k2.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k2.pk)},
                "roots": [root_entry(&r1)],
                "threshold": 1,
                "recoveryKeys": [rec_k1.keyid]
            }
        }),
        &[&rec_k2],
    );
    let rep_spent4 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc3_ok_rec.clone(),
                rc4_spent_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &base_opts,
    );
    let f_spent4 = find_check_finding(&rep_spent4, &rc4_spent_ref, "start").unwrap();
    assert_eq!(
        (
            &f_spent4.result[..],
            &f_spent4.code[..],
            f_spent4.about.as_deref()
        ),
        (
            "failed",
            "spent_recovery_key_retained",
            Some(rec_k1.keyid.as_str())
        )
    );
    // `report.start` advances through contiguous `ok` positions `1..3` while `chain` stays `dep_ref`!
    let st = rep_spent4.start.as_ref().unwrap();
    assert_eq!(st.chain.as_deref(), Some(dep_ref.as_str()));
    assert_eq!(st.head_seq, 3);
    assert_eq!(st.head_ref, rc3_ok_ref);

    // Row 30 (`quorum_not_configured` at seq = 4)
    let (rc4_no_quorum_cfg_ref, rc4_no_quorum_cfg_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r3.keyid,
            "actor": "actor:r3",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 4,
            "previous": rc3_ok_ref,
            "capturedAt": "2026-11-12T10:06:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": rc3_ok_ref,
                "authorization": "quorum",
                "signer": r3.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r3.pk)},
                "roots": [root_entry(&r1)],
                "threshold": 1
            }
        }),
        &[&r3],
    );
    let rep_r30 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc3_ok_rec,
                rc4_no_quorum_cfg_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &base_opts,
    );
    let f_r30 = find_check_finding(&rep_r30, &rc4_no_quorum_cfg_ref, "start").unwrap();
    assert_eq!(
        (&f_r30.result[..], &f_r30.code[..], f_r30.about.as_deref()),
        ("failed", "quorum_not_configured", None)
    );

    // 5. Veto-free `quorum_count` (§3.4):
    // - Duplicate retry of `(r1, alice, cust_k1)` on two separate streams + `(r2, bob, cust_k2)` -> counts as 2 (`ok`)!
    // - Conflicting approvals under `r1` (`(r1, alice, cust_k1)` AND `(r1, bob, cust_k2)`) -> disqualifies `r1` (`quorum_not_carried`, `need:2`)!
    // - Same custodian `(alice, cust_k1)` used under BOTH `r1` and `r2` -> disqualifies both (`quorum_not_carried`, `need:2`)!
    let (rc_quorum_ref, rc_quorum_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "urn:r5e:stream:acme:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T10:10:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "quorum",
                "signer": r1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)},
                "roots": [root_entry(&r3)],
                "threshold": 1
            }
        }),
        &[&r1],
    );
    let mk_app = |stream: &str, cap: &str, root_k: &TestKey, cust_id: &str, cust_k: &TestKey| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "RootChangeApproval",
                "schemaRef": rca_sref,
                "profileRef": dummy_prof_ref,
                "issuer": root_k.keyid,
                "actor": "actor:approver",
                "stream": stream,
                "seq": 1,
                "previous": null,
                "capturedAt": cap,
                "body": {
                    "change": rc_quorum_ref,
                    "root": root_k.keyid,
                    "custodian": cust_id,
                    "custodianKey": cust_k.keyid,
                    "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(cust_k.pk)}
                }
            }),
            &[root_k, cust_k],
        )
    };
    let (_, app_r1_alice_1) = mk_app(
        "stream:app-1",
        "2026-11-12T10:10:05Z",
        &r1,
        "mailto:alice@example.com",
        &cust_k1,
    );
    let (_, app_r1_alice_retry) = mk_app(
        "stream:app-2",
        "2026-11-12T10:10:06Z",
        &r1,
        "mailto:alice@example.com",
        &cust_k1,
    );
    let (_, app_r2_bob) = mk_app(
        "stream:app-3",
        "2026-11-12T10:10:07Z",
        &r2,
        "mailto:bob@example.com",
        &cust_k2,
    );
    let (_, app_r1_conflict_bob) = mk_app(
        "stream:app-4",
        "2026-11-12T10:10:08Z",
        &r1,
        "mailto:bob@example.com",
        &cust_k2,
    );
    let (_, app_r2_same_alice) = mk_app(
        "stream:app-5",
        "2026-11-12T10:10:09Z",
        &r2,
        "mailto:alice@example.com",
        &cust_k1,
    );

    // Retry of identical `(r1, alice, cust_k1)` + `(r2, bob, cust_k2)` -> `ok`!
    let rep_retry_ok = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                app_r1_alice_1.clone(),
                app_r1_alice_retry,
                app_r2_bob.clone(),
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &base_opts,
    );
    assert_eq!(
        find_check_finding(&rep_retry_ok, &rc_quorum_ref, "start")
            .unwrap()
            .code,
        "ok"
    );

    // Conflicting approvals under `r1` -> `quorum_not_carried` (`need:2`)!
    let rep_conflict = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                app_r1_alice_1.clone(),
                app_r1_conflict_bob,
                app_r2_bob,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &base_opts,
    );
    let f_conflict = find_check_finding(&rep_conflict, &rc_quorum_ref, "start").unwrap();
    assert_eq!(
        (
            &f_conflict.result[..],
            &f_conflict.code[..],
            f_conflict.about.as_deref()
        ),
        ("incomplete", "quorum_not_carried", Some("need:2"))
    );

    // Same custodian `(alice, cust_k1)` under both `r1` and `r2` -> `quorum_not_carried` (`need:2`)!
    let rep_shared_cust = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec,
                cs_rec,
                dep_rec,
                rc_quorum_rec,
                app_r1_alice_1,
                app_r2_same_alice,
            ],
            vec![],
            all_keys,
            vec![],
            vec![],
        ),
        &base_opts,
    );
    assert_eq!(
        find_check_finding(&rep_shared_cust, &rc_quorum_ref, "start")
            .unwrap()
            .code,
        "quorum_not_carried"
    );
}

#[test]
fn a6_slice2_root_change_approval_rows_a1_to_a15_and_late_bound_seals() {
    let pub_key = TestKey::from_seed(190);
    let boot = TestKey::from_seed(191);
    let r1 = TestKey::from_seed(192);
    let r2 = TestKey::from_seed(193);
    let rec_k = TestKey::from_seed(194);
    let alice_k = TestKey::from_seed(195);
    let wrong_k = TestKey::from_seed(196);
    let unkeyed_cust = TestKey::from_seed(197);
    let sealer = TestKey::from_seed(198);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let rc_sref = base_schema_ref("provenance.r5e.io/v2/RootsChanged");
    let rca_sref = base_schema_ref("provenance.r5e.io/v2/RootChangeApproval");
    let prin_sref = base_schema_ref("provenance.r5e.io/v2/Principal");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"a6-s2-app-prof");
    let full_defs = make_full_definitions_list();

    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-app",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );
    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:01:00Z",
            "body": {
                "deployment": "beta",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );

    // Deployment with TWO custodians:
    // - `mailto:bound@example.com` has inline `"key": wrong_k.keyid` (tests A12 when `alice_k` signs)
    // - `mailto:late@example.com` omits `"key"` (tests A13, A14, A15 late-bound custodian key!)
    let (dep_ref, dep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T11:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": r1.keyid,
                "roots": [{
                    "key": r1.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)}
                }],
                "threshold": 1,
                "recoveryKeys": [rec_k.keyid],
                "custodians": [
                    {"identity": "mailto:bound@example.com", "key": wrong_k.keyid},
                    {"identity": "mailto:late@example.com"}
                ]
            }
        }),
        &[&boot, &r1],
    );

    let (rc_quorum_ref, rc_quorum_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T11:10:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "quorum",
                "signer": r1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)},
                "roots": [{
                    "key": r2.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r2.pk)}
                }],
                "threshold": 1
            }
        }),
        &[&r1],
    );

    let all_keys = vec![
        pub_key.key_json(),
        boot.key_json(),
        r1.key_json(),
        r2.key_json(),
        rec_k.key_json(),
        alice_k.key_json(),
        wrong_k.key_json(),
        sealer.key_json(),
    ];
    let mut opts = VerifyOptions::default();
    opts.trusted_publishers.insert(pub_key.keyid.clone());
    opts.trusted_chain = Some(dep_ref.clone());

    // Row 2 on start stream: placing `RootChangeApproval` on `urn:r5e:stream:beta:start` -> `not_a_start_record`!
    let (app_on_start_ref, app_on_start_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let rep_on_start = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                app_on_start_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    assert_eq!(
        find_check_finding(&rep_on_start, &app_on_start_ref, "start")
            .unwrap()
            .code,
        "not_a_start_record"
    );

    // Off-stream A1 (`invalid_root_change_approval` via empty `reason`),
    // A2 (`unverified_root_change_approval` via `unkeyed_cust` missing from `keys`),
    // A3 (`approval_not_alone_on_stream` via `seq == 2` and via shared stream),
    // A4 (`approved_change_not_carried`),
    // A5 (`approval_not_for_quorum_change` citing an `Observation`),
    // A10 (`Principal` naming `alice_k` with `holder == "agent"` -> `approver_not_in_quorum`),
    // A11 (`custodian` not in `T.custodians` -> `approver_not_in_quorum`),
    // A12 (`mailto:bound@example.com` signed by `alice_k != wrong_k` -> `custodian_key_not_bound`).
    let (a1_ref, a1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)},
                "reason": ""
            }
        }),
        &[&r1, &alice_k],
    );
    let (a2_ref, a2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": unkeyed_cust.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(unkeyed_cust.pk)}
            }
        }),
        &[&r1, &unkeyed_cust],
    );
    let (a3_ref, a3_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:shared-a3",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let (obs_shared_ref, obs_shared_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": alice_k.keyid,
            "actor": "actor:alice",
            "stream": "stream:shared-a3",
            "seq": 2,
            "previous": a3_ref,
            "capturedAt": "2026-11-12T11:10:02Z",
            "body": {"topic": "shares-stream", "contentRefs": []}
        }),
        &[&alice_k],
    );
    let missing_change = evidence_ref_of(b"missing-roots-changed");
    let (a4_ref, a4_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a4",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": missing_change,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let (a5_ref, a5_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a5",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": obs_shared_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let (a11_ref, a11_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a11",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:nobody@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let (a12_ref, a12_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a12",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:01Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:bound@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );

    let rep_a_rows = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                a1_rec,
                a2_rec,
                a3_rec,
                obs_shared_rec,
                a4_rec,
                a5_rec,
                a11_rec,
                a12_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    for (subj, exp_res, exp_code, exp_about) in [
        (&a1_ref, "failed", "invalid_root_change_approval", None),
        (
            &a2_ref,
            "incomplete",
            "unverified_root_change_approval",
            None,
        ),
        (
            &a3_ref,
            "failed",
            "approval_not_alone_on_stream",
            Some("stream:shared-a3"),
        ),
        (
            &a4_ref,
            "incomplete",
            "approved_change_not_carried",
            Some(missing_change.as_str()),
        ),
        (
            &a5_ref,
            "failed",
            "approval_not_for_quorum_change",
            Some(obs_shared_ref.as_str()),
        ),
        (
            &a11_ref,
            "failed",
            "approver_not_in_quorum",
            Some("mailto:nobody@example.com"),
        ),
        (
            &a12_ref,
            "failed",
            "custodian_key_not_bound",
            Some(alice_k.keyid.as_str()),
        ),
    ] {
        let f = find_check_finding(&rep_a_rows, subj, "start").unwrap();
        assert_eq!(
            (&f.result[..], &f.code[..], f.about.as_deref()),
            (exp_res, exp_code, exp_about),
            "approval {subj}"
        );
    }

    // Rows A7 (`prior_start_not_carried`) and A8 (`approval_not_for_quorum_change` when `P.start == failed`):
    let missing_s3 = evidence_ref_of(b"missing-s3");
    let (rc_seq4_ref, rc_seq4_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 4,
            "previous": missing_s3,
            "capturedAt": "2026-11-12T11:15:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": missing_s3,
                "authorization": "quorum",
                "signer": r1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)},
                "roots": [{
                    "key": r2.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r2.pk)}
                }],
                "threshold": 1
            }
        }),
        &[&r1],
    );
    let (app_for_seq4_ref, app_for_seq4_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:a7-a8",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:15:01Z",
            "body": {
                "change": rc_seq4_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    // A7: seq = 3 absent -> `prior_start_not_carried` (`about = missing_s3`)
    let rep_a7 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_seq4_rec.clone(),
                app_for_seq4_rec.clone(),
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_a7 = find_check_finding(&rep_a7, &app_for_seq4_ref, "start").unwrap();
    assert_eq!(
        (&f_a7.result[..], &f_a7.code[..], f_a7.about.as_deref()),
        (
            "incomplete",
            "prior_start_not_carried",
            Some(missing_s3.as_str())
        )
    );
    // A8: seq = 3 present (`rc_quorum_rec`) with `rc_quorum_ref != missing_s3` -> `approval_not_for_quorum_change` (`about = rc_quorum_ref`)
    let rep_a8 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                rc_seq4_rec,
                app_for_seq4_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_a8 = find_check_finding(&rep_a8, &app_for_seq4_ref, "start").unwrap();
    assert_eq!(
        (&f_a8.result[..], &f_a8.code[..], f_a8.about.as_deref()),
        (
            "failed",
            "approval_not_for_quorum_change",
            Some(rc_quorum_ref.as_str())
        )
    );

    // Rows A10 (`Principal` agent check), A13, A14, and A15 (`mailto:late@example.com` late-bound custodian key!):
    let (app_late_ref, app_late_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:app-late",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:05Z",
            "body": {
                "change": rc_quorum_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );

    // A13a: No endorsement for `alice_k` -> `custodian_key_not_bound`
    let rep_a13a = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                app_late_rec.clone(),
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    assert_eq!(
        find_check_finding(&rep_a13a, &app_late_ref, "start")
            .unwrap()
            .code,
        "custodian_key_not_bound"
    );

    // Pre-change Endorsement `E` (`11:05Z < 11:10Z`) binding `alice_k` to `mailto:late@example.com` for `RootChangeApproval`!
    let (end_alice_ref, end_alice_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:end-alice",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:05:00Z",
            "body": {
                "subject": alice_k.keyid,
                "actsFor": "mailto:late@example.com",
                "kinds": ["provenance.r5e.io/v2/RootChangeApproval"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T11:00:00Z",
                "notAfter": "2026-11-12T12:00:00Z"
            }
        }),
        &[&r1],
    );

    // A14: `end_alice_rec` has `capturedAt < R.capturedAt` (`11:05 < 11:10`), NOT sealed -> `custodian_key_not_sealed_before_change` (`about = end_alice_ref`)!
    let rep_a14 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                end_alice_rec.clone(),
                app_late_rec.clone(),
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_a14 = find_check_finding(&rep_a14, &app_late_ref, "start").unwrap();
    assert_eq!(
        (&f_a14.result[..], &f_a14.code[..], f_a14.about.as_deref()),
        (
            "incomplete",
            "custodian_key_not_sealed_before_change",
            Some(end_alice_ref.as_str())
        )
    );

    // A15: Seal `end_alice_rec` at `11:06Z < 11:10Z` under `r1 -> sealer` (`EpochSeal`) -> both `app_late` AND `rc_quorum` become `ok`!
    let (_, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:end-sealer",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:03:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T11:00:00Z",
                "notAfter": "2026-11-12T12:00:00Z"
            }
        }),
        &[&r1],
    );
    let digest = r5e_verify_rs::provenance_v2::canonical::decode_hex_32(
        end_alice_ref.strip_prefix("evidence:sha256:").unwrap(),
    )
    .unwrap();
    let root_hash = format!("sha256:{}", hex_encode(&merkle_root(&[digest])));
    let (man_ref, man_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [end_alice_ref]
    }));
    let (seal_alice_ref, seal_alice_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": dummy_prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "stream:seal-ctrl",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:06:00Z",
            "body": {
                "stream": "stream:end-alice",
                "firstSeq": 1,
                "lastSeq": 1,
                "root": root_hash,
                "manifestRef": man_ref
            }
        }),
        &[&sealer],
    );

    let rep_a15 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                end_alice_rec.clone(),
                end_sealer_rec.clone(),
                seal_alice_rec.clone(),
                app_late_rec.clone(),
            ],
            vec![man_blob.clone()],
            all_keys.clone(),
            vec![json!(seal_alice_ref)],
            vec![],
        ),
        &opts,
    );
    assert_eq!(
        find_check_finding(&rep_a15, &app_late_ref, "start")
            .unwrap()
            .code,
        "ok"
    );
    assert_eq!(
        find_check_finding(&rep_a15, &rc_quorum_ref, "start")
            .unwrap()
            .code,
        "ok"
    );
    assert!(find_authority_finding(&rep_a15, &rc_quorum_ref).is_none());
    assert!(find_authority_finding(&rep_a15, &app_late_ref).is_none());

    // A13b: If `r1` revokes `end_alice_rec` at `11:08Z <= R.capturedAt`, `app_late` reverts to `custodian_key_not_bound`!
    let (_, rev_end_alice_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:rev-alice",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:08:00Z",
            "body": {"target": end_alice_ref}
        }),
        &[&r1],
    );
    let rep_a13_rev = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                end_alice_rec.clone(),
                end_sealer_rec.clone(),
                seal_alice_rec.clone(),
                rev_end_alice_rec,
                app_late_rec.clone(),
            ],
            vec![man_blob.clone()],
            all_keys.clone(),
            vec![json!(seal_alice_ref)],
            vec![],
        ),
        &opts,
    );
    assert_eq!(
        find_check_finding(&rep_a13_rev, &app_late_ref, "start")
            .unwrap()
            .code,
        "custodian_key_not_bound"
    );

    // Row 26 & A9 (`P` signature `incomplete` when `boot` key is omitted -> `unverified_start_record` with `about = dep_ref`)!
    let keys_without_boot: Vec<Value> = [&pub_key, &r1, &r2, &alice_k, &sealer]
        .iter()
        .map(|k| k.key_json())
        .collect();
    let rep_a9 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_quorum_rec.clone(),
                app_late_rec.clone(),
            ],
            vec![],
            keys_without_boot,
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_rc_26 = find_check_finding(&rep_a9, &rc_quorum_ref, "start").unwrap();
    assert_eq!(
        (
            &f_rc_26.result[..],
            &f_rc_26.code[..],
            f_rc_26.about.as_deref()
        ),
        (
            "incomplete",
            "unverified_start_record",
            Some(dep_ref.as_str())
        )
    );
    let f_app_a9 = find_check_finding(&rep_a9, &app_late_ref, "start").unwrap();
    assert_eq!(
        (
            &f_app_a9.result[..],
            &f_app_a9.code[..],
            f_app_a9.about.as_deref()
        ),
        (
            "incomplete",
            "unverified_start_record",
            Some(dep_ref.as_str())
        )
    );

    // A6 (`R` body `incomplete` via uncarried definition blob -> `unverified_start_record` with `about = rc_unver_ref`)!
    let uncarried_rc_sref = bytes_ref_of(b"uncarried-rc-def");
    let (rc_unver_ref, rc_unver_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": uncarried_rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "urn:r5e:stream:beta:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T11:10:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "quorum",
                "signer": r1.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r1.pk)},
                "threshold": 1,
                "roots": [{"key": r2.keyid, "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r2.pk)}}]
            }
        }),
        &[&r1],
    );
    let (app_a6_ref, app_a6_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r1.keyid,
            "actor": "actor:r1",
            "stream": "stream:app-a6",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:05Z",
            "body": {
                "change": rc_unver_ref,
                "root": r1.keyid,
                "custodian": "mailto:late@example.com",
                "custodianKey": alice_k.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)}
            }
        }),
        &[&r1, &alice_k],
    );
    let rep_a6 = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_unver_rec,
                app_a6_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    let f_app_a6 = find_check_finding(&rep_a6, &app_a6_ref, "start").unwrap();
    assert_eq!(
        (
            &f_app_a6.result[..],
            &f_app_a6.code[..],
            f_app_a6.about.as_deref()
        ),
        (
            "incomplete",
            "unverified_start_record",
            Some(rc_unver_ref.as_str())
        )
    );

    // A10 (`Principal` naming `alice_k` with `holder == "agent"` -> `approver_not_in_quorum`, `about = alice_k.keyid`)!
    let (_, prin_agent_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Principal",
            "schemaRef": prin_sref,
            "profileRef": dummy_prof_ref,
            "issuer": alice_k.keyid,
            "actor": "actor:alice",
            "stream": "stream:prin-alice",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:04:00Z",
            "body": {
                "key": alice_k.keyid,
                "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(alice_k.pk)},
                "holder": "agent"
            }
        }),
        &[&alice_k],
    );
    let rep_a10_agent = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec,
                cs_rec,
                dep_rec,
                rc_quorum_rec,
                end_alice_rec,
                end_sealer_rec,
                seal_alice_rec,
                prin_agent_rec,
                app_late_rec,
            ],
            vec![man_blob],
            all_keys,
            vec![json!(seal_alice_ref)],
            vec![],
        ),
        &opts,
    );
    let f_a10 = find_check_finding(&rep_a10_agent, &app_late_ref, "start").unwrap();
    assert_eq!(
        (&f_a10.result[..], &f_a10.code[..], f_a10.about.as_deref()),
        (
            "failed",
            "approver_not_in_quorum",
            Some(alice_k.keyid.as_str())
        )
    );
}

#[test]
fn a6_slice2_root_tenures_stray_approval_predated_grant_and_cross_root_revocation() {
    let pub_key = TestKey::from_seed(201);
    let boot = TestKey::from_seed(202);
    let r_old = TestKey::from_seed(203);
    let r_new = TestKey::from_seed(204);
    let rec_k = TestKey::from_seed(205);
    let worker = TestKey::from_seed(206);
    let sealer = TestKey::from_seed(207);
    let stranger_root = TestKey::from_seed(208);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let rc_sref = base_schema_ref("provenance.r5e.io/v2/RootsChanged");
    let rca_sref = base_schema_ref("provenance.r5e.io/v2/RootChangeApproval");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let rev_sref = base_schema_ref("provenance.r5e.io/v2/Revocation");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let dummy_prof_ref = bytes_ref_of(b"a6-s2-tenure-prof");
    let full_defs = make_full_definitions_list();

    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-ten",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );
    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:gamma:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:01:00Z",
            "body": {
                "deployment": "gamma",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let (dep_ref, dep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:gamma:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T12:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": r_old.keyid,
                "roots": [{
                    "key": r_old.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r_old.pk)}
                }],
                "threshold": 1,
                "recoveryKeys": [rec_k.keyid]
            }
        }),
        &[&boot, &r_old],
    );
    // Rotation `r_old -> r_new` at `13:00Z` via `rec_k`.
    let (rc_ref, rc_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": rc_sref,
            "profileRef": dummy_prof_ref,
            "issuer": rec_k.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:gamma:start",
            "seq": 3,
            "previous": dep_ref,
            "capturedAt": "2026-11-12T13:00:00Z",
            "body": {
                "chain": dep_ref,
                "replaces": dep_ref,
                "authorization": "recovery",
                "signer": rec_k.keyid,
                "signerKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(rec_k.pk)},
                "roots": [{
                    "key": r_new.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(r_new.pk)}
                }],
                "threshold": 1
            }
        }),
        &[&rec_k],
    );

    // 1. `r_new` endorsement dated BEFORE `S_3.capturedAt` (`12:30Z < 13:00Z`) -> `failed / not_covered / None` (§4.3.1)!
    let (end_predated_ref, end_predated_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_new.keyid,
            "actor": "actor:r-new",
            "stream": "stream:end-predated",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:30:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T12:00:00Z",
                "notAfter": "2026-11-12T15:00:00Z"
            }
        }),
        &[&r_new],
    );
    // 2. `r_new` endorsement dated AT/AFTER `S_3.capturedAt` (`13:05Z >= 13:00Z`) -> `ok`!
    let (end_new_ok_ref, end_new_ok_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_new.keyid,
            "actor": "actor:r-new",
            "stream": "stream:end-new-ok",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:05:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T13:00:00Z",
                "notAfter": "2026-11-12T15:00:00Z"
            }
        }),
        &[&r_new],
    );
    // 3. Stray failed `RootChangeApproval` on another stream (`approval_not_for_quorum_change`)
    //    leaves `r_new`'s established root tenure intact (§4.2.1)!
    let (stray_app_ref, stray_app_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": rca_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger_root.keyid,
            "actor": "actor:stranger",
            "stream": "stream:stray-app",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:01:00Z",
            "body": {
                "change": rc_ref,
                "root": stranger_root.keyid,
                "custodian": "mailto:stranger@example.com",
                "custodianKey": worker.keyid,
                "custodianPublicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(worker.pk)}
            }
        }),
        &[&stranger_root, &worker],
    );
    // 4. Stranger root `stranger_root` issues a parentless `Endorsement` `end_stranger_rec`,
    //    and active root `r_new` tries to revoke `end_stranger_rec` -> `failed / no_standing / r_new` (§4.3.2)!
    let (end_stranger_ref, end_stranger_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": stranger_root.keyid,
            "actor": "actor:stranger",
            "stream": "stream:end-stranger",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:02:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T13:00:00Z",
                "notAfter": "2026-11-12T15:00:00Z"
            }
        }),
        &[&stranger_root],
    );
    let (rev_stranger_by_rnew_ref, rev_stranger_by_rnew_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_new.keyid,
            "actor": "actor:r-new",
            "stream": "stream:rev-stranger-grant",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:10:00Z",
            "body": {"target": end_stranger_ref}
        }),
        &[&r_new],
    );

    // 5. Removed root `r_old` revoking its own earlier grant `end_old_rec`:
    //    - `rev_rold_late` at `13:20Z >= 13:00Z` unsealed -> `failed / ended / rc_ref`!
    //    - `rev_rold_early` at `12:40Z < 13:00Z` unsealed -> `incomplete / time_rests_on_the_signer / rc_ref`!
    let (end_old_ref, end_old_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_old.keyid,
            "actor": "actor:r-old",
            "stream": "stream:end-old",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:10:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T12:00:00Z",
                "notAfter": "2026-11-12T15:00:00Z"
            }
        }),
        &[&r_old],
    );
    let (rev_rold_late_ref, rev_rold_late_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_old.keyid,
            "actor": "actor:r-old",
            "stream": "stream:rev-rold-late",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:20:00Z",
            "body": {"target": end_old_ref}
        }),
        &[&r_old],
    );
    let (rev_rold_early_ref, rev_rold_early_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_old.keyid,
            "actor": "actor:r-old",
            "stream": "stream:rev-rold-early",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:40:00Z",
            "body": {"target": end_old_ref}
        }),
        &[&r_old],
    );

    let all_keys = vec![
        pub_key.key_json(),
        boot.key_json(),
        r_old.key_json(),
        r_new.key_json(),
        rec_k.key_json(),
        worker.key_json(),
        sealer.key_json(),
        stranger_root.key_json(),
    ];

    let mut opts_chain = VerifyOptions::default();
    opts_chain.trusted_publishers.insert(pub_key.keyid.clone());
    opts_chain.trusted_chain = Some(dep_ref.clone());

    let rep = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                cs_rec.clone(),
                dep_rec.clone(),
                rc_rec.clone(),
                end_predated_rec,
                end_new_ok_rec.clone(),
                stray_app_rec,
                end_stranger_rec,
                rev_stranger_by_rnew_rec,
                end_old_rec.clone(),
                rev_rold_late_rec,
                rev_rold_early_rec,
            ],
            vec![],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts_chain,
    );

    // Stray approval failed, yet `end_new_ok` still gets `authority == ok`!
    assert_eq!(
        find_check_finding(&rep, &stray_app_ref, "start")
            .unwrap()
            .code,
        "approval_not_for_quorum_change"
    );
    assert_eq!(
        find_authority_finding(&rep, &end_new_ok_ref).unwrap().code,
        "ok"
    );
    // Predated `r_new` grant -> `not_covered` (`about = None`)
    let f_pred = find_authority_finding(&rep, &end_predated_ref).unwrap();
    assert_eq!(
        (
            &f_pred.result[..],
            &f_pred.code[..],
            f_pred.about.as_deref()
        ),
        ("failed", "not_covered", None)
    );
    // Active root `r_new` revoking stranger's grant -> `no_standing` (`about = r_new`)
    let f_rev_str = find_authority_finding(&rep, &rev_stranger_by_rnew_ref).unwrap();
    assert_eq!(
        (
            &f_rev_str.result[..],
            &f_rev_str.code[..],
            f_rev_str.about.as_deref()
        ),
        ("failed", "no_standing", Some(r_new.keyid.as_str()))
    );
    // Removed root `r_old` revoking after/before removal without seal:
    let f_rold_late = find_authority_finding(&rep, &rev_rold_late_ref).unwrap();
    assert_eq!(
        (
            &f_rold_late.result[..],
            &f_rold_late.code[..],
            f_rold_late.about.as_deref()
        ),
        ("failed", "ended", Some(rc_ref.as_str()))
    );
    let f_rold_early = find_authority_finding(&rep, &rev_rold_early_ref).unwrap();
    assert_eq!(
        (
            &f_rold_early.result[..],
            &f_rold_early.code[..],
            f_rold_early.about.as_deref()
        ),
        (
            "incomplete",
            "time_rests_on_the_signer",
            Some(rc_ref.as_str())
        )
    );

    // 6. Direct `--trusted-root r_old` pin (§4.2.2):
    //    `rc_rec` gets `incomplete / new_roots_not_trusted` (`about = r_new.keyid`),
    //    `r_old`'s tenure is closed at `rc_ref` (so a post-change endorsement by `r_old` at `13:15Z` gets `ended`),
    //    and unpinned `r_new` gets `no_standing`!
    let (end_rold_post_ref, end_rold_post_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": r_old.keyid,
            "actor": "actor:r-old",
            "stream": "stream:end-rold-post",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:15:00Z",
            "body": {
                "subject": worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T13:00:00Z",
                "notAfter": "2026-11-12T15:00:00Z"
            }
        }),
        &[&r_old],
    );
    let _ = (obs_sref, seal_sref);
    let mut opts_pin_old = VerifyOptions::default();
    opts_pin_old
        .trusted_publishers
        .insert(pub_key.keyid.clone());
    opts_pin_old.trusted_roots = Some([r_old.keyid.clone()].into_iter().collect());

    let rep_pin = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec,
                cs_rec,
                dep_rec,
                rc_rec,
                end_rold_post_rec,
                end_new_ok_rec,
            ],
            vec![],
            all_keys,
            vec![],
            vec![],
        ),
        &opts_pin_old,
    );
    let f_rc_pin = find_check_finding(&rep_pin, &rc_ref, "start").unwrap();
    assert_eq!(
        (
            &f_rc_pin.result[..],
            &f_rc_pin.code[..],
            f_rc_pin.about.as_deref()
        ),
        (
            "incomplete",
            "new_roots_not_trusted",
            Some(r_new.keyid.as_str())
        )
    );
    let f_rold_post = find_authority_finding(&rep_pin, &end_rold_post_ref).unwrap();
    assert_eq!(
        (
            &f_rold_post.result[..],
            &f_rold_post.code[..],
            f_rold_post.about.as_deref()
        ),
        ("failed", "ended", Some(rc_ref.as_str()))
    );
    assert_eq!(
        find_authority_finding(&rep_pin, &end_new_ok_ref)
            .unwrap()
            .code,
        "no_standing"
    );
}

#[allow(clippy::too_many_arguments)]
fn make_retention_profile(
    schemas: Value,
    stream_prefix: &str,
    issuer_kids: &[&str],
    sealer_kids: &[&str],
    retention: Option<Value>,
) -> (String, Value) {
    let dummy_policy = bytes_ref_of(b"a7-policy");
    let mut prof = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": schemas,
        "authority": {
            "bindings": [{
                "streamPrefix": stream_prefix,
                "actorPrefixes": [
                    "actor:rec",
                    "actor:sealer",
                    "actor:root",
                    "actor:pub",
                    "actor:boot",
                    "actor:stranger"
                ],
                "issuerKeys": issuer_kids,
                "sealerKeys": sealer_kids,
            }],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "node",
            "requiredPayloads": "submitted",
            "onFailure": "refuse",
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": dummy_policy,
    });
    if let Some(ret) = retention {
        prof.as_object_mut()
            .unwrap()
            .insert("retention".to_string(), ret);
    }
    make_blob(&prof)
}

#[allow(clippy::too_many_arguments)]
fn make_seal_over_events(
    seal_sref: &str,
    prof_ref: &str,
    sealer: &TestKey,
    seal_stream: &str,
    sealed_stream: &str,
    first_seq: u64,
    last_seq: u64,
    captured_at: &str,
    event_refs: &[&str],
) -> (String, Value, Value) {
    let leaves: Vec<[u8; 32]> = event_refs.iter().map(|r| digest_of(r)).collect();
    let root = format!("sha256:{}", hex_encode(&merkle_root(&leaves)));
    let ev_vals: Vec<Value> = event_refs.iter().map(|r| json!(*r)).collect();
    let (man_ref, man_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": ev_vals
    }));
    let mut seal_body = json!({
        "stream": sealed_stream,
        "firstSeq": first_seq,
        "lastSeq": last_seq,
        "root": root,
        "manifestRef": man_ref
    });
    if first_seq > 1 {
        seal_body["previousSeal"] = json!(format!("evidence:sha256:{}", "e".repeat(64)));
    }
    let (seal_ref, seal_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": seal_stream,
            "seq": 1,
            "previous": null,
            "capturedAt": captured_at,
            "body": seal_body
        }),
        &[sealer],
    );
    (seal_ref, seal_rec, man_blob)
}

#[test]
fn a7_target_holds_until_boundaries_self_content_carveout_and_earliest_disposal() {
    let root = TestKey::from_seed(211);
    let recorder = TestKey::from_seed(212);
    let releaser = TestKey::from_seed(213);
    let sealer = TestKey::from_seed(214);
    let stranger = TestKey::from_seed(215);

    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let hold_sref = base_schema_ref("provenance.r5e.io/v2/RetentionHold");
    let rel_sref = base_schema_ref("provenance.r5e.io/v2/RetentionHoldRelease");
    let disp_sref = base_schema_ref("provenance.r5e.io/v2/PayloadDisposition");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");

    let schemas = json!({
        "provenance.r5e.io/v2/Endorsement": end_sref,
        "provenance.r5e.io/v2/Observation": obs_sref,
        "provenance.r5e.io/v2/RetentionHold": hold_sref,
        "provenance.r5e.io/v2/RetentionHoldRelease": rel_sref,
        "provenance.r5e.io/v2/PayloadDisposition": disp_sref,
        "provenance.r5e.io/v2/EpochSeal": seal_sref,
    });
    let (prof_ref, prof_blob) = make_retention_profile(
        schemas,
        "urn:r5e:stream:d1:",
        &[&recorder.keyid, &root.keyid, &sealer.keyid],
        &[&sealer.keyid],
        Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 60
        })),
    );

    let (_, end_rec_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d1:auth-rec",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:00:00Z",
            "body": {
                "subject": recorder.keyid,
                "kinds": [
                    "provenance.r5e.io/v2/Observation",
                    "provenance.r5e.io/v2/RetentionHold",
                    "provenance.r5e.io/v2/RetentionHoldRelease",
                    "provenance.r5e.io/v2/PayloadDisposition"
                ],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_rel_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d1:auth-rel",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:00:00Z",
            "body": {
                "subject": releaser.keyid,
                "kinds": ["provenance.r5e.io/v2/RetentionHoldRelease"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_seal_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d1:auth-seal",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:00:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );

    let all_keys = vec![
        root.key_json(),
        recorder.key_json(),
        releaser.key_json(),
        sealer.key_json(),
        stranger.key_json(),
    ];
    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    let missing_b1 = bytes_ref_of(b"missing-payload-b1");
    let missing_b2 = bytes_ref_of(b"missing-payload-b2");
    let missing_hold_detail = bytes_ref_of(b"missing-hold-detail-blob");

    // Two observations on `urn:r5e:stream:d1:app`: `obs1` references `missing_b1`, `obs2` references `missing_b2`.
    let (obs1_ref, obs1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:app",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:00:00Z",
            "body": {"topic": "t1", "contentRefs": [missing_b1]}
        }),
        &[&recorder],
    );
    let (obs2_ref, obs2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:app2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:00:00Z",
            "body": {"topic": "t2", "contentRefs": [missing_b2]}
        }),
        &[&recorder],
    );

    // (1) Target-based `RetentionHold` (`targets: [missing_b1, obs2_ref]`) + §4.4 self-content exclusion:
    //     `H.body.targets` mentions `missing_b1` (MUST NOT emit a `content` finding on `H`),
    //     while `H.body.details` mentions `missing_hold_detail` (MUST emit `not_carried` on `H`)!
    let (hold_targets_ref, hold_targets_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHold",
            "schemaRef": hold_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:05:00Z",
            "body": {
                "targets": [missing_b1, obs2_ref],
                "reason": "litigation target hold",
                "until": "2026-11-12T13:00:00+01:00",
                "details": {"memo": missing_hold_detail}
            }
        }),
        &[&recorder],
    );

    // Stranger forges/signs a non-counting `RetentionHold` dated `2099` on `H.stream` (`seq: 2` with wrong authority):
    // `T_end(H.stream)` MUST ignore non-counting records (`T_end == 11:05:00Z < 12:00:00Z`)!
    let (_, stranger_future_hold_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHold",
            "schemaRef": hold_sref,
            "profileRef": prof_ref,
            "issuer": stranger.keyid,
            "actor": "actor:stranger",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": hold_targets_ref,
            "capturedAt": "2099-01-01T00:00:00Z",
            "body": {
                "targets": [missing_b1],
                "reason": "forged future clock push"
            }
        }),
        &[&stranger],
    );

    // Check Row 8 (`missing_under_hold`) for both `targets: [missing_b1]` (on `obs1`) and `targets: [obs2_ref]` (on `obs2`),
    // plus Row 8 carve-out when `omissions` has `reason: "withheld"` vs `reason: "expired"`:
    let mut b_missing_hold = empty_bundle_with(
        vec![
            end_rec_rec.clone(),
            end_rel_rec.clone(),
            end_seal_rec.clone(),
            obs1_rec.clone(),
            obs2_rec.clone(),
            hold_targets_rec.clone(),
            stranger_future_hold_rec,
        ],
        vec![prof_blob.clone()],
        all_keys.clone(),
        vec![],
        vec![],
    );
    b_missing_hold["omissions"] = json!([
        {"ref": missing_b1, "reason": "expired"}
    ]);
    let rep_mh = verify_bundle_value(&b_missing_hold, &opts);
    // `obs1` (`reason: "expired"` does NOT bypass Row 8!) and `obs2` (no omission) both get `missing_under_hold` (`about = hold_targets_ref`)!
    for obs_r in [&obs1_ref, &obs2_ref] {
        let fc = find_check_finding(&rep_mh, obs_r, "content").unwrap();
        assert_eq!(
            (&fc.result[..], &fc.code[..], fc.about.as_deref()),
            (
                "incomplete",
                "missing_under_hold",
                Some(hold_targets_ref.as_str())
            )
        );
    }
    // `hold_targets_rec` gets EXACTLY ONE `content` finding (for `details.memo == missing_hold_detail`, NOT `targets`)!
    let hold_content_findings: Vec<_> = rep_mh
        .findings
        .iter()
        .filter(|f| f.subject == hold_targets_ref && f.check == "content")
        .collect();
    assert_eq!(hold_content_findings.len(), 1);
    assert_eq!(
        (
            &hold_content_findings[0].result[..],
            &hold_content_findings[0].code[..],
            hold_content_findings[0].about.as_deref()
        ),
        (
            "incomplete",
            "not_carried",
            Some(missing_hold_detail.as_str())
        )
    );

    // Row 8 carve-out: when `omissions` carries `reason: "withheld"` for `missing_b1` and `"not-selected"` for `missing_b2`,
    // Row 8 does NOT fire — they emit `omitted_withheld` and `omitted_not_selected`!
    b_missing_hold["omissions"] = json!([
        {"ref": missing_b1, "reason": "withheld"},
        {"ref": missing_b2, "reason": "not-selected"}
    ]);
    let rep_carve = verify_bundle_value(&b_missing_hold, &opts);
    assert_eq!(
        find_check_finding(&rep_carve, &obs1_ref, "content")
            .unwrap()
            .code,
        "omitted_withheld"
    );
    assert_eq!(
        find_check_finding(&rep_carve, &obs2_ref, "content")
            .unwrap()
            .code,
        "omitted_not_selected"
    );

    // (2a) `T_end(H.stream) == H.until` boundary on Row 8:
    //      Adding a counting record on `urn:r5e:stream:d1:retention` at `12:00:00Z` (`== H.until`) advances `T_end` to `H.until`,
    //      so `T_end < H.until` is FALSE and `obs1` / `obs2` pass Row 8 (`not_carried`)!
    let other_blob_ref = bytes_ref_of(b"unrelated-target");
    let (_, clock_advance_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHold",
            "schemaRef": hold_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": hold_targets_ref,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {
                "targets": [other_blob_ref],
                "reason": "unrelated hold at exact until instant"
            }
        }),
        &[&recorder],
    );
    let rep_tend_eq = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_rec_rec.clone(),
                end_seal_rec.clone(),
                obs1_rec.clone(),
                obs2_rec.clone(),
                hold_targets_rec.clone(),
                clock_advance_rec,
            ],
            vec![prof_blob.clone()],
            all_keys.clone(),
            vec![],
            vec![],
        ),
        &opts,
    );
    assert_eq!(
        find_check_finding(&rep_tend_eq, &obs1_ref, "content")
            .unwrap()
            .code,
        "not_carried"
    );
    assert_eq!(
        find_check_finding(&rep_tend_eq, &obs2_ref, "content")
            .unwrap()
            .code,
        "not_carried"
    );

    // (2b) `D.capturedAt < H.until` vs `D.capturedAt == H.until` boundary on Row 1 (`disposed_under_hold`):
    //      - `disp_before_until` at `11:59:59.999999999Z` (< `12:00:00Z`) -> `failed / disposed_under_hold / hold_targets_ref`
    //        for BOTH `obs1` (`targets: [missing_b1]`) and `obs2` (`targets: [obs2_ref]`)!
    //      - `disp_at_until` at `13:00:00+01:00` (`== 12:00:00Z`!) -> passes Row 1 -> `incomplete / disposed_by_record / disp_at_until_ref`!
    //      Also checks §4.4 self-content exclusion on `PayloadDisposition.body.targets`!
    let (disp_before_ref, disp_before_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": hold_targets_ref,
            "capturedAt": "2026-11-12T11:59:59.999999999Z",
            "body": {
                "targets": [missing_b1, obs2_ref],
                "action": "deleted",
                "reason": "1ns too early"
            }
        }),
        &[&recorder],
    );
    let (seal_db_ref, seal_db_rec, man_db_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:d1:seal-db",
        "urn:r5e:stream:d1:retention",
        1,
        2,
        "2026-11-12T12:05:00Z",
        &[&hold_targets_ref, &disp_before_ref],
    );
    let rep_d_lt = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_rec_rec.clone(),
                end_seal_rec.clone(),
                obs1_rec.clone(),
                obs2_rec.clone(),
                hold_targets_rec.clone(),
                disp_before_rec,
                seal_db_rec,
            ],
            vec![prof_blob.clone(), man_db_blob],
            all_keys.clone(),
            vec![json!(seal_db_ref)],
            vec![],
        ),
        &opts,
    );
    for obs_r in [&obs1_ref, &obs2_ref] {
        let fc = find_check_finding(&rep_d_lt, obs_r, "content").unwrap();
        assert_eq!(
            (&fc.result[..], &fc.code[..], fc.about.as_deref()),
            (
                "failed",
                "disposed_under_hold",
                Some(hold_targets_ref.as_str())
            )
        );
    }
    // `disp_before_rec` has NO `content` finding on itself (`targets` excluded under §4.4)!
    assert!(find_check_finding(&rep_d_lt, &disp_before_ref, "content").is_none());

    let (disp_eq_ref, disp_eq_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": hold_targets_ref,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {
                "targets": [missing_b1, obs2_ref],
                "action": "expired",
                "reason": "exact until instant across +01:00 offset"
            }
        }),
        &[&recorder],
    );
    let (seal_deq_ref, seal_deq_rec, man_deq_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:d1:seal-deq",
        "urn:r5e:stream:d1:retention",
        1,
        2,
        "2026-11-12T12:05:00Z",
        &[&hold_targets_ref, &disp_eq_ref],
    );
    let rep_d_eq = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_rec_rec.clone(),
                end_seal_rec.clone(),
                obs1_rec.clone(),
                obs2_rec.clone(),
                hold_targets_rec.clone(),
                disp_eq_rec,
                seal_deq_rec,
            ],
            vec![prof_blob.clone(), man_deq_blob],
            all_keys.clone(),
            vec![json!(seal_deq_ref)],
            vec![],
        ),
        &opts,
    );
    for obs_r in [&obs1_ref, &obs2_ref] {
        let fc = find_check_finding(&rep_d_eq, obs_r, "content").unwrap();
        assert_eq!(
            (&fc.result[..], &fc.code[..], fc.about.as_deref()),
            (
                "incomplete",
                "disposed_by_record",
                Some(disp_eq_ref.as_str())
            )
        );
    }

    // (3) Second lawful `PayloadDisposition` (`seq = 4`) CANNOT mask an earlier unlawful `PayloadDisposition` (`seq = 2` under hold,
    //     followed by 2-signer `RetentionHoldRelease` at `seq = 3` and lawful `PayloadDisposition` at `seq = 4`)!
    let (rel_ref, rel_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHoldRelease",
            "schemaRef": rel_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 3,
            "previous": disp_before_ref,
            "capturedAt": "2026-11-12T11:30:00Z",
            "body": {
                "hold": hold_targets_ref,
                "releasedBy": releaser.keyid,
                "reason": "released after premature disposal"
            }
        }),
        &[&recorder, &releaser],
    );
    let (disp_later_lawful_ref, disp_later_lawful_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 4,
            "previous": rel_ref,
            "capturedAt": "2026-11-12T11:35:00Z",
            "body": {
                "targets": [missing_b1],
                "action": "deleted",
                "reason": "re-logged after release"
            }
        }),
        &[&recorder],
    );
    let (_, disp_before_rec_again) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": hold_targets_ref,
            "capturedAt": "2026-11-12T11:20:00Z",
            "body": {
                "targets": [missing_b1],
                "action": "deleted",
                "reason": "unlawful early disposal while held"
            }
        }),
        &[&recorder],
    );
    // Re-bind `rel_rec` & `disp_later_lawful_rec` onto `disp_before_rec_again`'s exact ref:
    let early_disp_ref = disp_before_rec_again["ref"].as_str().unwrap().to_string();
    let (rel2_ref, rel2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHoldRelease",
            "schemaRef": rel_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 3,
            "previous": early_disp_ref,
            "capturedAt": "2026-11-12T11:30:00Z",
            "body": {
                "hold": hold_targets_ref,
                "releasedBy": releaser.keyid,
                "reason": "released after premature disposal"
            }
        }),
        &[&recorder, &releaser],
    );
    let (disp2_lawful_ref, disp2_lawful_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 4,
            "previous": rel2_ref,
            "capturedAt": "2026-11-12T11:35:00Z",
            "body": {
                "targets": [missing_b1],
                "action": "deleted",
                "reason": "re-logged after release"
            }
        }),
        &[&recorder],
    );
    let _ = (rel_rec, disp_later_lawful_ref, disp_later_lawful_rec);
    let (seal_seq4_ref, seal_seq4_rec, man_seq4_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:d1:seal-s4",
        "urn:r5e:stream:d1:retention",
        1,
        4,
        "2026-11-12T11:40:00Z",
        &[
            &hold_targets_ref,
            &early_disp_ref,
            &rel2_ref,
            &disp2_lawful_ref,
        ],
    );
    let rep_earliest = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_rec_rec.clone(),
                end_rel_rec,
                end_seal_rec.clone(),
                obs1_rec.clone(),
                hold_targets_rec,
                disp_before_rec_again,
                rel2_rec,
                disp2_lawful_rec,
                seal_seq4_rec,
            ],
            vec![prof_blob.clone(), man_seq4_blob],
            all_keys.clone(),
            vec![json!(seal_seq4_ref)],
            vec![],
        ),
        &opts,
    );
    let fc_earliest = find_check_finding(&rep_earliest, &obs1_ref, "content").unwrap();
    assert_eq!(
        (
            &fc_earliest.result[..],
            &fc_earliest.code[..],
            fc_earliest.about.as_deref()
        ),
        (
            "failed",
            "disposed_under_hold",
            Some(hold_targets_ref.as_str())
        )
    );

    // Also verify early `disposed_before_keep_until` (`seq = 1` at `11:00:30Z` < `11:01:00Z`) followed by lawful `seq = 2` at `11:05:00Z`!
    let (d_too_soon_ref, d_too_soon_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:00:30Z",
            "body": {
                "targets": [missing_b1],
                "action": "expired",
                "reason": "30s < 60s keepContentForSeconds"
            }
        }),
        &[&recorder],
    );
    let (d_ok_later_ref, d_ok_later_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 2,
            "previous": d_too_soon_ref,
            "capturedAt": "2026-11-12T11:05:00Z",
            "body": {
                "targets": [missing_b1],
                "action": "expired",
                "reason": "later valid disposal"
            }
        }),
        &[&recorder],
    );
    let (seal_k_ref, seal_k_rec, man_k_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:d1:seal-k",
        "urn:r5e:stream:d1:retention",
        1,
        2,
        "2026-11-12T11:06:00Z",
        &[&d_too_soon_ref, &d_ok_later_ref],
    );
    let rep_keep = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_rec_rec.clone(),
                end_seal_rec.clone(),
                obs1_rec.clone(),
                d_too_soon_rec,
                d_ok_later_rec,
                seal_k_rec,
            ],
            vec![prof_blob.clone(), man_k_blob],
            all_keys.clone(),
            vec![json!(seal_k_ref)],
            vec![],
        ),
        &opts,
    );
    let fc_keep = find_check_finding(&rep_keep, &obs1_ref, "content").unwrap();
    assert_eq!(
        (
            &fc_keep.result[..],
            &fc_keep.code[..],
            fc_keep.about.as_deref()
        ),
        (
            "failed",
            "disposed_before_keep_until",
            Some(d_too_soon_ref.as_str())
        )
    );

    // (4) `PayloadDisposition` with `action: "restored"` NEVER covers `(R, B)` (falls through to §5.3)!
    let (d_restored_ref, d_restored_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d1:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T11:10:00Z",
            "body": {
                "targets": [missing_b1],
                "action": "restored",
                "reason": "restored from cold backup"
            }
        }),
        &[&recorder],
    );
    let (seal_res_ref, seal_res_rec, man_res_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:d1:seal-res",
        "urn:r5e:stream:d1:retention",
        1,
        1,
        "2026-11-12T11:11:00Z",
        &[&d_restored_ref],
    );
    let mut b_restored = empty_bundle_with(
        vec![
            end_rec_rec,
            end_seal_rec,
            obs1_rec,
            d_restored_rec,
            seal_res_rec,
        ],
        vec![prof_blob, man_res_blob],
        all_keys,
        vec![json!(seal_res_ref)],
        vec![],
    );
    b_restored["omissions"] = json!([{"ref": missing_b1, "reason": "expired"}]);
    let rep_restored = verify_bundle_value(&b_restored, &opts);
    let fc_res = find_check_finding(&rep_restored, &obs1_ref, "content").unwrap();
    assert_eq!(
        (
            &fc_res.result[..],
            &fc_res.code[..],
            fc_res.about.as_deref()
        ),
        ("incomplete", "omitted_expired", Some(missing_b1.as_str()))
    );
}

#[test]
fn a7_two_missing_refs_one_disposal_profile_only_pinned_chain_and_i128_bounds() {
    let pub_key = TestKey::from_seed(221);
    let boot = TestKey::from_seed(222);
    let root = TestKey::from_seed(223);
    let recorder = TestKey::from_seed(224);
    let sealer = TestKey::from_seed(225);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let cs_sref = base_schema_ref("provenance.r5e.io/v2/ChainStarted");
    let dep_sref = base_schema_ref("provenance.r5e.io/v2/Deployment");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let obs_sref = base_schema_ref("provenance.r5e.io/v2/Observation");
    let disp_sref = base_schema_ref("provenance.r5e.io/v2/PayloadDisposition");
    let seal_sref = base_schema_ref("provenance.r5e.io/v2/EpochSeal");

    let schemas = json!({
        "provenance.r5e.io/v2/DefinitionPublished": def_pub_sref,
        "provenance.r5e.io/v2/ChainStarted": cs_sref,
        "provenance.r5e.io/v2/Deployment": dep_sref,
        "provenance.r5e.io/v2/Endorsement": end_sref,
        "provenance.r5e.io/v2/Observation": obs_sref,
        "provenance.r5e.io/v2/PayloadDisposition": disp_sref,
        "provenance.r5e.io/v2/EpochSeal": seal_sref,
    });
    let (prof_zero_ref, prof_zero_blob) = make_retention_profile(
        schemas.clone(),
        "urn:r5e:stream:d2:",
        &[&recorder.keyid, &sealer.keyid, &root.keyid, &pub_key.keyid],
        &[&sealer.keyid],
        Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 0
        })),
    );
    let (prof_untrusted_seal_ref, prof_untrusted_seal_blob) = make_retention_profile(
        schemas.clone(),
        "urn:r5e:stream:d2:",
        &[&sealer.keyid],
        &[&sealer.keyid],
        None,
    );
    let (prof_max_keep_ref, prof_max_keep_blob) = make_retention_profile(
        schemas,
        "urn:r5e:stream:d2:",
        &[&recorder.keyid, &sealer.keyid],
        &[&sealer.keyid],
        Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": 9_007_199_254_740_991_i64
        })),
    );

    let full_defs = make_full_definitions_list();
    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": prof_zero_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "urn:r5e:stream:d2:pub",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:00:00Z",
            "body": {"definitions": full_defs}
        }),
        &[&pub_key],
    );

    // (5) Single record `obs_two_rec` with TWO distinct missing `bytes:` refs (`b1`, `b2`, plus duplicate `b1` in `details`)
    //     covered by the SAME `PayloadDisposition` `disp_scope_rec` (`keepContentForSeconds: 0` at exact `capturedAt`!)
    //     AND verified in (6) Profile-only trust mode (`trustedProfiles` without `trustedRoots` or `trustedChain`)!
    let b1 = bytes_ref_of(b"multi-ref-1");
    let b2 = bytes_ref_of(b"multi-ref-2");
    let (obs_two_ref, obs_two_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_zero_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d2:work",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T14:00:00Z",
            "session": "session:run-42",
            "body": {
                "topic": "two-missing",
                "contentRefs": [b1, b2],
                "details": {"echo": b1}
            }
        }),
        &[&recorder],
    );
    let (disp_scope_ref, disp_scope_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_zero_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d2:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T14:00:00Z",
            "body": {
                "scope": "session:run-42",
                "action": "expired",
                "reason": "session TTL 0s expired"
            }
        }),
        &[&recorder],
    );
    let (seal_ok_ref, seal_ok_rec, man_ok_blob) = make_seal_over_events(
        &seal_sref,
        &prof_zero_ref,
        &sealer,
        "urn:r5e:stream:d2:seals",
        "urn:r5e:stream:d2:retention",
        1,
        1,
        "2026-11-12T14:00:00Z",
        &[&disp_scope_ref],
    );

    let mut opts_prof = VerifyOptions::default();
    opts_prof.trusted_publishers.insert(pub_key.keyid.clone());
    opts_prof.trusted_profiles.insert(prof_zero_ref.clone());
    opts_prof.trusted_profiles.insert(prof_max_keep_ref.clone());

    let rep_prof = verify_bundle_value(
        &empty_bundle_with(
            vec![
                p_rec.clone(),
                obs_two_rec.clone(),
                disp_scope_rec.clone(),
                seal_ok_rec.clone(),
            ],
            vec![prof_zero_blob.clone(), man_ok_blob.clone()],
            vec![pub_key.key_json(), recorder.key_json(), sealer.key_json()],
            vec![json!(seal_ok_ref)],
            vec![],
        ),
        &opts_prof,
    );
    let two_content: Vec<_> = rep_prof
        .findings
        .iter()
        .filter(|f| f.subject == obs_two_ref && f.check == "content")
        .collect();
    // MUST emit TWO `content` findings (one for `b1`, one for `b2`, NOT 3 for duplicate `b1` and NOT deduplicated to 1)!
    assert_eq!(two_content.len(), 2);
    for fc in &two_content {
        assert_eq!(
            (&fc.result[..], &fc.code[..], fc.about.as_deref()),
            (
                "incomplete",
                "disposed_by_record",
                Some(disp_scope_ref.as_str())
            )
        );
    }
    assert_eq!(rep_prof.summary.failed, 0);
    assert_eq!(rep_prof.summary.incomplete, 2);

    // (6b) Profile-only trust mode when the seal's own profile (`prof_untrusted_seal_ref`) is NOT in `trustedProfiles`:
    //      `S` fails `profile_bounds == "ok"` so `S` is NOT a qualifying seal -> `disposal_not_sealed`!
    let (seal_untrusted_ref, seal_untrusted_rec, man_untrusted_blob) = make_seal_over_events(
        &seal_sref,
        &prof_untrusted_seal_ref,
        &sealer,
        "urn:r5e:stream:d2:seals-untrusted",
        "urn:r5e:stream:d2:retention",
        1,
        1,
        "2026-11-12T14:00:00Z",
        &[&disp_scope_ref],
    );
    let rep_untrusted_seal = verify_bundle_value(
        &empty_bundle_with(
            vec![
                obs_two_rec.clone(),
                disp_scope_rec.clone(),
                seal_untrusted_rec,
            ],
            vec![
                prof_zero_blob.clone(),
                prof_untrusted_seal_blob,
                man_untrusted_blob,
            ],
            vec![recorder.key_json(), sealer.key_json()],
            vec![json!(seal_untrusted_ref)],
            vec![],
        ),
        &opts_prof,
    );
    let fc_uns = find_check_finding(&rep_untrusted_seal, &obs_two_ref, "content").unwrap();
    assert_eq!(
        (
            &fc_uns.result[..],
            &fc_uns.code[..],
            fc_uns.about.as_deref()
        ),
        (
            "incomplete",
            "disposal_not_sealed",
            Some(disp_scope_ref.as_str())
        )
    );

    // (5b) Huge `keepContentForSeconds = 9_007_199_254_740_991` (`2^53 - 1`) without `i128` overflow
    //      AND Row 6 `O(1)` guard when `D.seq = 9_007_199_254_740_991`!
    let b_huge = bytes_ref_of(b"huge-keep-payload");
    let (obs_huge_ref, obs_huge_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_max_keep_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d2:huge",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T14:00:00Z",
            "body": {"topic": "max-keep", "contentRefs": [b_huge]}
        }),
        &[&recorder],
    );
    let (disp_huge_keep_ref, disp_huge_keep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_max_keep_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d2:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "9999-12-31T23:59:59.999999999Z",
            "body": {
                "scope": "stream:urn:r5e:stream:d2:huge",
                "action": "expired",
                "reason": "still way before 2^53 - 1 seconds"
            }
        }),
        &[&recorder],
    );
    let rep_huge_keep = verify_bundle_value(
        &empty_bundle_with(
            vec![obs_huge_rec, disp_huge_keep_rec],
            vec![prof_max_keep_blob],
            vec![recorder.key_json()],
            vec![],
            vec![],
        ),
        &opts_prof,
    );
    let fc_hk = find_check_finding(&rep_huge_keep, &obs_huge_ref, "content").unwrap();
    assert_eq!(
        (&fc_hk.result[..], &fc_hk.code[..], fc_hk.about.as_deref()),
        (
            "failed",
            "disposed_before_keep_until",
            Some(disp_huge_keep_ref.as_str())
        )
    );

    // Row 6 `O(1)` guard with `D.seq = 9_007_199_254_740_991` (`previous` set to dummy ref, sealed):
    let dummy_prev = format!("evidence:sha256:{}", "c".repeat(64));
    let (disp_huge_seq_ref, disp_huge_seq_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_zero_ref,
            "issuer": recorder.keyid,
            "actor": "actor:rec",
            "stream": "urn:r5e:stream:d2:retention",
            "seq": 9_007_199_254_740_991_i64,
            "previous": dummy_prev,
            "capturedAt": "2026-11-12T14:05:00Z",
            "body": {
                "scope": "session:run-42",
                "action": "deleted",
                "reason": "huge seq without prior retention stream"
            }
        }),
        &[&recorder],
    );
    let (seal_hs_ref, seal_hs_rec, man_hs_blob) = make_seal_over_events(
        &seal_sref,
        &prof_zero_ref,
        &sealer,
        "urn:r5e:stream:d2:seals-hs",
        "urn:r5e:stream:d2:retention",
        9_007_199_254_740_991,
        9_007_199_254_740_991,
        "2026-11-12T14:06:00Z",
        &[&disp_huge_seq_ref],
    );
    let rep_hs = verify_bundle_value(
        &empty_bundle_with(
            vec![obs_two_rec.clone(), disp_huge_seq_rec, seal_hs_rec],
            vec![prof_zero_blob.clone(), man_hs_blob],
            vec![recorder.key_json(), sealer.key_json()],
            vec![json!(seal_hs_ref)],
            vec![],
        ),
        &opts_prof,
    );
    let fc_hs = find_check_finding(&rep_hs, &obs_two_ref, "content").unwrap();
    assert_eq!(
        (&fc_hs.result[..], &fc_hs.code[..], fc_hs.about.as_deref()),
        (
            "incomplete",
            "disposed_holds_not_shown",
            Some(disp_huge_seq_ref.as_str())
        )
    );

    // (7) Pinned chain (`trustedChain`) both ESTABLISHED (`disposed_by_record`) and UNESTABLISHED (`chain_not_carried` -> `omitted_expired`)!
    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": prof_zero_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:d2:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:01:00Z",
            "body": {
                "deployment": "d2",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": full_defs
            }
        }),
        &[&boot],
    );
    let (dep_ref, dep_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": dep_sref,
            "profileRef": prof_zero_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:d2:start",
            "seq": 2,
            "previous": cs_ref,
            "capturedAt": "2026-11-12T13:02:00Z",
            "body": {
                "accepts": cs_ref,
                "bootstrap": boot.keyid,
                "claimedBy": root.keyid,
                "roots": [{
                    "key": root.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(root.pk)}
                }],
                "threshold": 1
            }
        }),
        &[&boot, &root],
    );
    let (_, end_rec_chain) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_zero_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d2:end-rec",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:05:00Z",
            "body": {
                "subject": recorder.keyid,
                "kinds": [
                    "provenance.r5e.io/v2/Observation",
                    "provenance.r5e.io/v2/PayloadDisposition"
                ],
                "mayEndorse": false,
                "notBefore": "2026-11-12T13:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_seal_chain) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_zero_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d2:end-seal",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T13:05:00Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-12T13:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );

    let mut b_chain = empty_bundle_with(
        vec![
            p_rec,
            cs_rec,
            dep_rec,
            end_rec_chain.clone(),
            end_seal_chain.clone(),
            obs_two_rec.clone(),
            disp_scope_rec.clone(),
            seal_ok_rec.clone(),
        ],
        vec![prof_zero_blob.clone(), man_ok_blob.clone()],
        vec![
            pub_key.key_json(),
            boot.key_json(),
            root.key_json(),
            recorder.key_json(),
            sealer.key_json(),
        ],
        vec![json!(seal_ok_ref)],
        vec![],
    );
    b_chain["omissions"] = json!([
        {"ref": b1, "reason": "expired"},
        {"ref": b2, "reason": "expired"}
    ]);

    let mut opts_chain_est = VerifyOptions::default();
    opts_chain_est
        .trusted_publishers
        .insert(pub_key.keyid.clone());
    opts_chain_est.trusted_chain = Some(dep_ref);
    let rep_chain_est = verify_bundle_value(&b_chain, &opts_chain_est);
    let fc_est = find_check_finding(&rep_chain_est, &obs_two_ref, "content").unwrap();
    assert_eq!(
        (
            &fc_est.result[..],
            &fc_est.code[..],
            fc_est.about.as_deref()
        ),
        (
            "incomplete",
            "disposed_by_record",
            Some(disp_scope_ref.as_str())
        )
    );

    // Unestablished `trustedChain` (start stream omitted from bundle): `authority` is `chain_not_carried`,
    // so `disp_scope_rec` does NOT count under §4.2 and `obs_two_rec` falls through to §5.3 (`omitted_expired`)!
    let mut b_chain_unest = empty_bundle_with(
        vec![
            end_rec_chain,
            end_seal_chain,
            obs_two_rec,
            disp_scope_rec,
            seal_ok_rec,
        ],
        vec![prof_zero_blob, man_ok_blob],
        vec![root.key_json(), recorder.key_json(), sealer.key_json()],
        vec![json!(seal_ok_ref)],
        vec![],
    );
    b_chain_unest["omissions"] = json!([
        {"ref": b1, "reason": "expired"},
        {"ref": b2, "reason": "expired"}
    ]);
    let rep_chain_unest = verify_bundle_value(&b_chain_unest, &opts_chain_est);
    assert_eq!(
        find_authority_finding(&rep_chain_unest, &obs_two_ref)
            .unwrap()
            .code,
        "chain_not_carried"
    );
    let unest_content: Vec<_> = rep_chain_unest
        .findings
        .iter()
        .filter(|f| f.subject == obs_two_ref && f.check == "content")
        .collect();
    assert_eq!(unest_content.len(), 2);
    assert_eq!(unest_content[0].code, "omitted_expired");
    assert_eq!(unest_content[1].code, "omitted_expired");
}

#[test]
fn a7_multi_signer_ordinary_kind_under_trusted_roots() {
    let pub_key = TestKey::from_seed(231);
    let root = TestKey::from_seed(232);
    let s1_ok = TestKey::from_seed(233);
    let s2_ok = TestKey::from_seed(234);
    let s_stranger = TestKey::from_seed(235);
    let s_inc1 = TestKey::from_seed(236);
    let s_inc2 = TestKey::from_seed(237);
    let s_expired = TestKey::from_seed(238);
    let uncarried_gw1 = TestKey::from_seed(239);
    let uncarried_gw2 = TestKey::from_seed(240);

    let def_pub_sref = base_schema_ref("provenance.r5e.io/v2/DefinitionPublished");
    let end_sref = base_schema_ref("provenance.r5e.io/v2/Endorsement");
    let badge_sref = base_schema_ref("provenance.r5e.io/v2/Badge");

    // Custom 2-signer ordinary kind `custom.example.io/v1/DualSign` (`signatures: 2`)
    let dual_kind = "custom.example.io/v1/DualSign";
    let (dual_sref, dual_def_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": dual_kind,
        "signatures": 2,
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["cosigner", "note"],
            "properties": {
                "cosigner": {"type": "string", "matchesSigner": 2},
                "note": {"type": "string"}
            }
        }
    }));

    let mut defs_list = make_full_definitions_list();
    defs_list.push(json!({"kind": dual_kind, "schemaRef": dual_sref}));
    defs_list.sort_by(|a, b| a["kind"].as_str().cmp(&b["kind"].as_str()));

    let dummy_prof_ref = bytes_ref_of(b"a7-multisig-prof");
    let (_, pub_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": def_pub_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "stream:pub-dual",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:00:00Z",
            "body": {"definitions": defs_list}
        }),
        &[&pub_key],
    );

    let (end_s1_ref, end_s1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-s1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:01:00Z",
            "body": {
                "subject": s1_ok.keyid,
                "kinds": [dual_kind],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_s2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-s2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:01:00Z",
            "body": {
                "subject": s2_ok.keyid,
                "kinds": [dual_kind],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&root],
    );
    // Expired grant for `s_expired` (`outside_window` at `12:00Z`):
    let (end_exp_ref, end_exp_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": dummy_prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "stream:end-exp",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:01:00Z",
            "body": {
                "subject": s_expired.keyid,
                "kinds": [dual_kind],
                "mayEndorse": false,
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T11:00:00Z"
            }
        }),
        &[&root],
    );
    // Badges for `s_inc1` and `s_inc2` citing uncarried parent grants `missing_p1` and `missing_p2` (`chain_not_carried`):
    let missing_p1 = format!("evidence:sha256:{}", "1".repeat(64));
    let missing_p2 = format!("evidence:sha256:{}", "2".repeat(64));
    let (_, badge_inc1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": uncarried_gw1.keyid,
            "actor": "actor:gw1",
            "stream": "stream:b-inc1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:05:00Z",
            "body": {
                "subject": s_inc1.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(s_inc1.pk)},
                "holder": "inc1",
                "parent": missing_p1,
                "kinds": [dual_kind],
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&uncarried_gw1, &s_inc1],
    );
    let (_, badge_inc2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Badge",
            "schemaRef": badge_sref,
            "profileRef": dummy_prof_ref,
            "issuer": uncarried_gw2.keyid,
            "actor": "actor:gw2",
            "stream": "stream:b-inc2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T10:05:00Z",
            "body": {
                "subject": s_inc2.keyid,
                "subjectKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(s_inc2.pk)},
                "holder": "inc2",
                "parent": missing_p2,
                "kinds": [dual_kind],
                "notBefore": "2026-11-12T10:00:00Z",
                "notAfter": "2026-11-12T20:00:00Z"
            }
        }),
        &[&uncarried_gw2, &s_inc2],
    );

    // Case 8a: Both `s1_ok` and `s2_ok` authorised -> `ok / ok / Some(end_s1_ref)` (`about_1`)!
    let (rec_both_ok_ref, rec_both_ok) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s1_ok.keyid,
            "actor": "actor:s1",
            "stream": "stream:dual-ok",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s2_ok.keyid, "note": "both ok"}
        }),
        &[&s1_ok, &s2_ok],
    );
    // Case 8b: Signer 1 `ok`, Signer 2 `s_stranger` unauthorised -> `failed / no_standing / Some(s_stranger.keyid)`!
    let (rec_s2_bad_ref, rec_s2_bad) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s1_ok.keyid,
            "actor": "actor:s1",
            "stream": "stream:dual-s2-bad",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s_stranger.keyid, "note": "s2 unauthorized"}
        }),
        &[&s1_ok, &s_stranger],
    );
    // Case 8c: Signer 1 `incomplete` (`s_inc1`) + Signer 2 `failed` (`s_stranger`) -> `failed` beats `incomplete`!
    let (rec_inc_then_fail_ref, rec_inc_then_fail) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s_inc1.keyid,
            "actor": "actor:inc1",
            "stream": "stream:dual-inc-fail",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s_stranger.keyid, "note": "failed beats incomplete"}
        }),
        &[&s_inc1, &s_stranger],
    );
    // Case 8d: Both signers `failed` (`s_expired` -> `not_covered`, `s_stranger` -> `no_standing`) -> lowest index 1 wins in BOTH orders!
    let _ = end_exp_ref;
    let (rec_both_fail_ref, rec_both_fail) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s_expired.keyid,
            "actor": "actor:exp",
            "stream": "stream:dual-both-fail",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s_stranger.keyid, "note": "both failed"}
        }),
        &[&s_expired, &s_stranger],
    );
    let (rec_both_fail_rev_ref, rec_both_fail_rev) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s_stranger.keyid,
            "actor": "actor:stranger",
            "stream": "stream:dual-both-fail-rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s_expired.keyid, "note": "both failed reversed"}
        }),
        &[&s_stranger, &s_expired],
    );
    // Case 8e: Both signers `incomplete` (`s_inc1` -> `missing_p1`, `s_inc2` -> `missing_p2`) -> lowest index 1 wins!
    let (rec_both_inc_ref, rec_both_inc) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "profileRef": dummy_prof_ref,
            "schemaRef": dual_sref,
            "issuer": s_inc1.keyid,
            "actor": "actor:inc1",
            "stream": "stream:dual-both-inc",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s_inc2.keyid, "note": "both incomplete"}
        }),
        &[&s_inc1, &s_inc2],
    );
    // Case 8f: Envelope with only 1 signature (`len != 2`) signed by authorised `s1_ok`:
    //          `body` -> `signature_count_differs_from_definition`, AND `authority` -> `failed / not_covered / None`!
    let (rec_one_sig_ref, rec_one_sig) = make_signed_record(
        &json!({
            "apiVersion": "custom.example.io/v1",
            "kind": "DualSign",
            "schemaRef": dual_sref,
            "profileRef": dummy_prof_ref,
            "issuer": s1_ok.keyid,
            "actor": "actor:s1",
            "stream": "stream:dual-one-sig",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-12T12:00:00Z",
            "body": {"cosigner": s2_ok.keyid, "note": "missing second signature"}
        }),
        &[&s1_ok],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_publishers.insert(pub_key.keyid.clone());
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    let rep = verify_bundle_value(
        &empty_bundle_with(
            vec![
                pub_rec,
                end_s1_rec,
                end_s2_rec,
                end_exp_rec,
                badge_inc1_rec,
                badge_inc2_rec,
                rec_both_ok,
                rec_s2_bad,
                rec_inc_then_fail,
                rec_both_fail,
                rec_both_fail_rev,
                rec_both_inc,
                rec_one_sig,
            ],
            vec![dual_def_blob],
            vec![
                pub_key.key_json(),
                root.key_json(),
                s1_ok.key_json(),
                s2_ok.key_json(),
                s_stranger.key_json(),
                s_inc1.key_json(),
                s_inc2.key_json(),
                s_expired.key_json(),
                uncarried_gw1.key_json(),
                uncarried_gw2.key_json(),
            ],
            vec![],
            vec![],
        ),
        &opts,
    );

    // 8a: both ok -> `ok`, `about == end_s1_ref`
    let f_ok = find_authority_finding(&rep, &rec_both_ok_ref).unwrap();
    assert_eq!(
        (&f_ok.result[..], &f_ok.code[..], f_ok.about.as_deref()),
        ("ok", "ok", Some(end_s1_ref.as_str()))
    );
    // 8b: s2 unauthorized -> `failed / no_standing / s_stranger`
    let f_s2_bad = find_authority_finding(&rep, &rec_s2_bad_ref).unwrap();
    assert_eq!(
        (
            &f_s2_bad.result[..],
            &f_s2_bad.code[..],
            f_s2_bad.about.as_deref()
        ),
        ("failed", "no_standing", Some(s_stranger.keyid.as_str()))
    );
    // 8c: s1 incomplete + s2 failed -> `failed` beats `incomplete` (`no_standing`, `s_stranger`)
    let f_inc_fail = find_authority_finding(&rep, &rec_inc_then_fail_ref).unwrap();
    assert_eq!(
        (
            &f_inc_fail.result[..],
            &f_inc_fail.code[..],
            f_inc_fail.about.as_deref()
        ),
        ("failed", "no_standing", Some(s_stranger.keyid.as_str()))
    );
    // 8d: both failed -> signer 1 wins tie in both directions (`not_covered` when `s_expired` is first; `no_standing` when `s_stranger` is first)
    let f_both_fail = find_authority_finding(&rep, &rec_both_fail_ref).unwrap();
    assert_eq!(
        (
            &f_both_fail.result[..],
            &f_both_fail.code[..],
            f_both_fail.about.as_deref()
        ),
        ("failed", "not_covered", None)
    );
    let f_both_fail_rev = find_authority_finding(&rep, &rec_both_fail_rev_ref).unwrap();
    assert_eq!(
        (
            &f_both_fail_rev.result[..],
            &f_both_fail_rev.code[..],
            f_both_fail_rev.about.as_deref()
        ),
        ("failed", "no_standing", Some(s_stranger.keyid.as_str()))
    );
    // 8e: both incomplete -> signer 1 (`chain_not_carried`, `missing_p1`) wins tie
    let f_both_inc = find_authority_finding(&rep, &rec_both_inc_ref).unwrap();
    assert_eq!(
        (
            &f_both_inc.result[..],
            &f_both_inc.code[..],
            f_both_inc.about.as_deref()
        ),
        ("incomplete", "chain_not_carried", Some(missing_p1.as_str()))
    );
    // 8f: 1-signature envelope on 2-signer kind -> `body: signature_count_differs_from_definition` AND `authority: failed / not_covered / None`
    let f_one_body = find_check_finding(&rep, &rec_one_sig_ref, "body").unwrap();
    assert_eq!(
        (
            &f_one_body.result[..],
            &f_one_body.code[..],
            f_one_body.about.as_deref()
        ),
        ("failed", "signature_count_differs_from_definition", None)
    );
    let f_one_auth = find_authority_finding(&rep, &rec_one_sig_ref).unwrap();
    assert_eq!(
        (
            &f_one_auth.result[..],
            &f_one_auth.code[..],
            f_one_auth.about.as_deref()
        ),
        ("failed", "not_covered", None)
    );
}

#[test]
fn a9_definition_grammar_bounds_sets_and_typed_cross_chain_refs() {
    // 1. Valid definition exercising `unique: true`, `keys` (including negative lookahead),
    //    `maxEntries`, `maxLength` on multi-type node, `ref: {evidence: true}`, and
    //    `ref: {evidence: true, crossChain: true}`.
    let def_json = json!({
        "format": "r5e.kind-definition/v1",
        "kind": "acme.example/v1/A9Check",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["setField", "boundedMap", "evRef", "xRef"],
            "properties": {
                "setField": {
                    "type": "array",
                    "unique": true,
                    "items": {"type": "object"}
                },
                "boundedMap": {
                    "type": "object",
                    "keys": "^(?!reserved$)[a-z][a-z0-9_]{0,15}$",
                    "maxEntries": 2,
                    "properties": {
                        "declared": {"type": "string", "maxLength": 4}
                    },
                    "values": {
                        "type": ["string", "integer", "boolean"],
                        "maxLength": 4
                    }
                },
                "evRef": {
                    "type": "ref",
                    "ref": {"evidence": true}
                },
                "xRef": {
                    "type": "ref",
                    "ref": {"evidence": true, "crossChain": true}
                }
            }
        }
    });
    let def_bytes = encode_canonical_json(&def_json).unwrap().into_bytes();
    let parsed = ParsedDefinition::parse(&def_bytes).expect("valid A9 definition");

    let ev_a = format!("evidence:sha256:{}", "a".repeat(64));
    let ev_b = format!("evidence:sha256:{}", "b".repeat(64));
    let chain_c = format!("evidence:sha256:{}", "c".repeat(64));
    let valid_body = json!({
        "setField": [{"a": 1, "b": 2}, {"a": 1, "b": 3}],
        "boundedMap": {"declared": "éé", "extra_1": 99999999},
        "evRef": ev_a,
        "xRef": format!("chain:{chain_c}/{ev_b}"),
    });
    assert!(parsed.validate_body(&valid_body, &[]));

    // Direct evidence ref also accepted on `crossChain: true`:
    let mut direct_xref = valid_body.clone();
    direct_xref["xRef"] = json!(ev_b);
    assert!(parsed.validate_body(&direct_xref, &[]));

    // Duplicate object items with different key construction order fail `unique: true`:
    let mut dup_set = valid_body.clone();
    let mut m1 = serde_json::Map::new();
    m1.insert("x".into(), json!(1));
    m1.insert("y".into(), json!([true, {"z": 2}]));
    let mut m2 = serde_json::Map::new();
    m2.insert("y".into(), json!([true, {"z": 2}]));
    m2.insert("x".into(), json!(1));
    dup_set["setField"] = json!([Value::Object(m1), Value::Object(m2)]);
    assert!(!parsed.validate_body(&dup_set, &[]));

    // `maxLength: 4` counts UTF-8 bytes ("ééé" = 3 chars, 6 UTF-8 bytes -> fails):
    let mut too_long_utf8 = valid_body.clone();
    too_long_utf8["boundedMap"]["extra_1"] = json!("ééé");
    assert!(!parsed.validate_body(&too_long_utf8, &[]));
    too_long_utf8["boundedMap"]["extra_1"] = json!(true);
    assert!(parsed.validate_body(&too_long_utf8, &[]));

    // `maxEntries: 2` rejects 3 entries:
    let mut too_many = valid_body.clone();
    too_many["boundedMap"] = json!({"declared": "ab", "k1": 1, "k2": 2});
    assert!(!parsed.validate_body(&too_many, &[]));

    // `keys` rejects both lookahead-excluded key ("reserved") and trailing newline ("ok\n"):
    let mut bad_key_reserved = valid_body.clone();
    bad_key_reserved["boundedMap"] = json!({"reserved": 1});
    assert!(!parsed.validate_body(&bad_key_reserved, &[]));
    let mut bad_key_nl = valid_body.clone();
    bad_key_nl["boundedMap"] = json!({"abc\n": 1});
    assert!(!parsed.validate_body(&bad_key_nl, &[]));

    // `evRef` rejects `bytes:` and `chain:` when `crossChain` is not enabled:
    let mut bad_ev = valid_body.clone();
    bad_ev["evRef"] = json!(format!("bytes:sha256:{}", "a".repeat(64)));
    assert!(!parsed.validate_body(&bad_ev, &[]));
    bad_ev["evRef"] = json!(format!("chain:{chain_c}/{ev_a}"));
    assert!(!parsed.validate_body(&bad_ev, &[]));

    // `xRef` rejects label chain name, `bytes:` chain name, `bytes:` inner ref, and 2-hop `chain:`:
    for bad_xref in [
        format!("chain:r5e-dev/{ev_b}"),
        format!("chain:bytes:sha256:{}/{ev_b}", "c".repeat(64)),
        format!("chain:{chain_c}/bytes:sha256:{}", "b".repeat(64)),
        format!("chain:{chain_c}/chain:{chain_c}/{ev_b}"),
    ] {
        let mut b = valid_body.clone();
        b["xRef"] = json!(bad_xref);
        assert!(
            !parsed.validate_body(&b, &[]),
            "expected failure for {bad_xref}"
        );
    }

    // 2. Definition-level compile rejections (`definition_not_available` -> `ParsedDefinition::parse == None`):
    let bad_defs = [
        // `unique: false`
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "array", "unique": false}}}}),
        // `unique: true` on non-array
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "string", "unique": true}}}}),
        // `keys` on non-object
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "string", "keys": "^a$"}}}}),
        // `keys` uncompilable regex
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"keys": "[unclosed"}}),
        // `maxEntries` <= 0 or on non-object
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"maxEntries": 0}}),
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "array", "maxEntries": 2}}}}),
        // `maxLength` <= 0 or on node admitting no string
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "string", "maxLength": 0}}}}),
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": ["integer", "boolean"], "maxLength": 10}}}}),
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "ref", "ref": {"bytes": true}, "maxLength": 80}}}}),
        // `ref` on non-ref type or `crossChain: false` or `evidence: false`
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "string", "ref": {"evidence": true}}}}}),
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "ref", "ref": {"evidence": true, "crossChain": false}}}}}),
        json!({"format": "r5e.kind-definition/v1", "kind": "x/v1/K", "schema": {"properties": {"a": {"type": "ref", "ref": {"evidence": false}}}}}),
    ];
    for bd in bad_defs {
        let bytes = encode_canonical_json(&bd).unwrap().into_bytes();
        assert!(
            ParsedDefinition::parse(&bytes).is_none(),
            "expected definition compile failure for {bd}"
        );
    }
}

#[test]
fn a9_seal_chain_excludes_failed_seals_from_authority_and_retention_coverage() {
    let root = TestKey::from_seed(231);
    let actor_key = TestKey::from_seed(232);
    let sealer = TestKey::from_seed(233);
    let pub_key = TestKey::from_seed(234);

    let base = r5e_verify_rs::provenance_v2::default_base_definitions();
    let idx_val: Value = serde_json::from_slice(include_bytes!(
        "../vendor/provenance-v2/definitions/index.json"
    ))
    .unwrap();
    let obs_sref = idx_val["provenance.r5e.io/v2/Observation"]
        .as_str()
        .unwrap()
        .to_string();
    let end_sref = idx_val["provenance.r5e.io/v2/Endorsement"]
        .as_str()
        .unwrap()
        .to_string();
    let rev_sref = idx_val["provenance.r5e.io/v2/Revocation"]
        .as_str()
        .unwrap()
        .to_string();
    let disp_sref = idx_val["provenance.r5e.io/v2/PayloadDisposition"]
        .as_str()
        .unwrap()
        .to_string();
    let seal_sref = idx_val["provenance.r5e.io/v2/EpochSeal"]
        .as_str()
        .unwrap()
        .to_string();
    let dp_sref = idx_val["provenance.r5e.io/v2/DefinitionPublished"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(base.contains_index_ref(&obs_sref));

    let prof_val = json!({
        "format": "r5e.capture-profile/v2",
        "schemas": {
            "provenance.r5e.io/v2/Observation": obs_sref,
            "provenance.r5e.io/v2/Endorsement": end_sref,
            "provenance.r5e.io/v2/Revocation": rev_sref,
            "provenance.r5e.io/v2/PayloadDisposition": disp_sref,
            "provenance.r5e.io/v2/EpochSeal": seal_sref,
            "provenance.r5e.io/v2/DefinitionPublished": dp_sref,
        },
        "authority": {
            "bindings": [{
                "streamPrefix": "urn:r5e:stream:d9:",
                "actorPrefixes": ["actor:op", "actor:root", "actor:sealer", "actor:pub"],
                "issuerKeys": [root.keyid, actor_key.keyid, sealer.keyid, pub_key.keyid],
                "sealerKeys": [sealer.keyid],
            }],
            "checkpointKeys": [],
        },
        "durability": {
            "failureDomain": "node",
            "requiredPayloads": "submitted",
            "onFailure": "refuse",
        },
        "retention": {
            "disposal": "by-record",
            "keepContentForSeconds": 60,
        },
        "policyRequiredKinds": [],
        "deploymentPolicyRef": bytes_ref_of(b"pol"),
    });
    let (prof_ref, prof_blob) = make_blob(&prof_val);

    let (_, dp_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": dp_sref,
            "profileRef": prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "urn:r5e:stream:d9:pub",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T09:00:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/Observation", "definition": obs_sref},
                    {"kind": "provenance.r5e.io/v2/Endorsement", "definition": end_sref},
                    {"kind": "provenance.r5e.io/v2/Revocation", "definition": rev_sref},
                    {"kind": "provenance.r5e.io/v2/PayloadDisposition", "definition": disp_sref},
                    {"kind": "provenance.r5e.io/v2/EpochSeal", "definition": seal_sref},
                    {"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": dp_sref},
                ]
            }
        }),
        &[&pub_key],
    );

    // Root endorses both `actor_key` and `sealer`.
    let (end_actor_ref, end_actor_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d9:id",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T09:00:00Z",
            "body": {
                "subject": actor_key.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation", "provenance.r5e.io/v2/PayloadDisposition"],
                "mayEndorse": false,
                "notBefore": "2026-11-15T09:00:00Z",
                "notAfter": "2026-11-15T18:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d9:id",
            "seq": 2,
            "previous": end_actor_ref,
            "capturedAt": "2026-11-15T09:00:01Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-15T09:00:00Z",
                "notAfter": "2026-11-15T18:00:00Z"
            }
        }),
        &[&root],
    );

    // `actor_key` writes `obs1` (seq 1) and `obs2` (seq 2, at 10:00:00Z, missing content),
    // and root revokes `end_actor_ref` at 12:00:00Z!
    // Without a valid seal fixing `obs2` before 12:00:00Z, `obs2` gets `incomplete / time_rests_on_the_signer`.
    let missing_blob_ref = bytes_ref_of(b"disposed-observation-content");
    let (obs1_ref, obs1_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": actor_key.keyid,
            "actor": "actor:op",
            "stream": "urn:r5e:stream:d9:work",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T09:59:00Z",
            "body": {
                "topic": "audit.step",
                "contentRefs": []
            }
        }),
        &[&actor_key],
    );
    let (obs2_ref, obs2_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_ref,
            "issuer": actor_key.keyid,
            "actor": "actor:op",
            "stream": "urn:r5e:stream:d9:work",
            "seq": 2,
            "previous": obs1_ref,
            "capturedAt": "2026-11-15T10:00:00Z",
            "session": "session:s9",
            "body": {
                "topic": "audit.step",
                "contentRefs": [missing_blob_ref]
            }
        }),
        &[&actor_key],
    );
    let (rev_ref, rev_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:d9:rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T12:00:00Z",
            "body": {
                "target": end_actor_ref,
                "reason": "key retired"
            }
        }),
        &[&root],
    );

    // Retention stream seq 1 disposes `missing_blob_ref` at 10:05:00Z (> keepContentForSeconds=60s, before 12:00 revocation).
    let (disp_ref, disp_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": disp_sref,
            "profileRef": prof_ref,
            "issuer": actor_key.keyid,
            "actor": "actor:op",
            "stream": "urn:r5e:stream:d9:retention",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T10:05:00Z",
            "body": {
                "targets": [missing_blob_ref],
                "action": "expired",
                "reason": "retention window elapsed"
            }
        }),
        &[&actor_key],
    );

    // Bad work seal (`firstSeq: 2` with NO `previousSeal` -> `seal_chain: failed / seal_predecessor_missing`,
    // tested with BOTH a carried epoch manifest AND a Merkle membership proof!).
    let work_leaf = [obs2_ref
        .strip_prefix("evidence:sha256:")
        .unwrap()
        .as_bytes()];
    let _ = work_leaf;
    let obs2_digest = {
        let mut out = [0u8; 32];
        let hex_s = obs2_ref.strip_prefix("evidence:sha256:").unwrap();
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex_s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    let work_root = format!("sha256:{}", hex_encode(&merkle_root(&[obs2_digest])));
    let (work_man_ref, work_man_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [obs2_ref]
    }));
    let (bad_work_seal_ref, bad_work_seal_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "urn:r5e:stream:d9:seals-w",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T10:01:00Z",
            "body": {
                "stream": "urn:r5e:stream:d9:work",
                "firstSeq": 2,
                "lastSeq": 2,
                "root": work_root,
                "manifestRef": work_man_ref
            }
        }),
        &[&sealer],
    );

    // Bad retention seal (`firstSeq: 1` WITH `previousSeal` -> `seal_chain: failed / first_seal_names_a_predecessor`).
    let disp_digest = {
        let mut out = [0u8; 32];
        let hex_s = disp_ref.strip_prefix("evidence:sha256:").unwrap();
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex_s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    let ret_root = format!("sha256:{}", hex_encode(&merkle_root(&[disp_digest])));
    let (ret_man_ref, ret_man_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [disp_ref]
    }));
    let (bad_ret_seal_ref, bad_ret_seal_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "urn:r5e:stream:d9:seals-r",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T10:06:00Z",
            "body": {
                "stream": "urn:r5e:stream:d9:retention",
                "firstSeq": 1,
                "lastSeq": 1,
                "previousSeal": format!("evidence:sha256:{}", "7".repeat(64)),
                "root": ret_root,
                "manifestRef": ret_man_ref
            }
        }),
        &[&sealer],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_publishers
        .insert(format!("{}=r5e.io", pub_key.keyid));
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    let rep = verify_bundle_value(
        &empty_bundle_with(
            vec![
                dp_rec,
                end_actor_rec,
                end_sealer_rec,
                obs1_rec,
                obs2_rec,
                rev_rec,
                disp_rec,
                bad_work_seal_rec,
                bad_ret_seal_rec.clone(),
            ],
            vec![prof_blob, work_man_blob, ret_man_blob.clone()],
            vec![
                root.key_json(),
                actor_key.key_json(),
                sealer.key_json(),
                pub_key.key_json(),
            ],
            vec![json!(bad_work_seal_ref), json!(bad_ret_seal_ref)],
            vec![json!({
                "record": obs2_ref,
                "seal": bad_work_seal_ref,
                "index": 0,
                "siblings": []
            })],
        ),
        &opts,
    );

    // Both seals get `epoch: ok` (and `membership: ok`), AND `seal_chain: failed` (layer 3)!
    let sc_w = rep
        .findings
        .iter()
        .find(|f| f.layer == 3 && f.subject == bad_work_seal_ref && f.check == "seal_chain")
        .unwrap();
    assert_eq!(
        (&sc_w.result[..], &sc_w.code[..], sc_w.about.as_deref()),
        ("failed", "seal_predecessor_missing", None)
    );
    let sc_r = rep
        .findings
        .iter()
        .find(|f| f.layer == 3 && f.subject == bad_ret_seal_ref && f.check == "seal_chain")
        .unwrap();
    assert_eq!(
        (&sc_r.result[..], &sc_r.code[..], sc_r.about.as_deref()),
        ("failed", "first_seal_names_a_predecessor", None)
    );
    assert_eq!(
        rep.findings
            .iter()
            .find(|f| f.layer == 3 && f.subject == obs2_ref && f.check == "membership")
            .unwrap()
            .result,
        "ok"
    );

    // Because `bad_work_seal_ref` failed `seal_chain`, it MUST NOT fix `obs2` or `disp` in time under §6.3a:
    let auth_obs2 = find_authority_finding(&rep, &obs2_ref).unwrap();
    assert_eq!(
        (
            &auth_obs2.result[..],
            &auth_obs2.code[..],
            auth_obs2.about.as_deref()
        ),
        (
            "incomplete",
            "time_rests_on_the_signer",
            Some(rev_ref.as_str())
        )
    );

    // And under profile-only mode (where `authority` on `disp` is `ok`), `bad_ret_seal_ref` failing `seal_chain`
    // MUST exclude it from §6.4a retention seal coverage (`disposal_not_sealed` instead of `disposed_by_record`)!
    let mut prof_opts = VerifyOptions::default();
    prof_opts
        .trusted_publishers
        .insert(format!("{}=r5e.io", pub_key.keyid));
    prof_opts.trusted_profiles.insert(prof_ref);
    let (prof_obs_ref, prof_obs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": obs_sref,
            "profileRef": prof_opts.trusted_profiles.iter().next().unwrap(),
            "issuer": actor_key.keyid,
            "actor": "actor:op",
            "stream": "urn:r5e:stream:d9:work2",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T10:00:00Z",
            "body": {
                "topic": "audit.step",
                "contentRefs": [missing_blob_ref]
            }
        }),
        &[&actor_key],
    );
    let rep_prof = verify_bundle_value(
        &empty_bundle_with(
            vec![
                prof_obs_rec,
                make_signed_record(
                    &json!({
                        "apiVersion": "provenance.r5e.io/v2",
                        "kind": "PayloadDisposition",
                        "schemaRef": disp_sref,
                        "profileRef": prof_opts.trusted_profiles.iter().next().unwrap(),
                        "issuer": actor_key.keyid,
                        "actor": "actor:op",
                        "stream": "urn:r5e:stream:d9:retention",
                        "seq": 1,
                        "previous": null,
                        "capturedAt": "2026-11-15T10:05:00Z",
                        "body": {
                            "targets": [missing_blob_ref],
                            "action": "expired",
                            "reason": "retention window elapsed"
                        }
                    }),
                    &[&actor_key],
                )
                .1,
                bad_ret_seal_rec,
            ],
            vec![make_blob(&prof_val).1, ret_man_blob],
            vec![actor_key.key_json(), sealer.key_json()],
            vec![json!(bad_ret_seal_ref)],
            vec![],
        ),
        &prof_opts,
    );
    let content_f = find_check_finding(&rep_prof, &prof_obs_ref, "content").unwrap();
    assert_eq!(
        (
            &content_f.result[..],
            &content_f.code[..],
            content_f.about.as_deref()
        ),
        ("incomplete", "disposal_not_sealed", Some(disp_ref.as_str()))
    );
}

#[test]
fn a9_publisher_domains_union_chain_started_cli_and_wasm_ffi() {
    let pub_key = TestKey::from_seed(241);
    let boot = TestKey::from_seed(242);

    let idx_val: Value = serde_json::from_slice(include_bytes!(
        "../vendor/provenance-v2/definitions/index.json"
    ))
    .unwrap();
    let cs_sref = idx_val["provenance.r5e.io/v2/ChainStarted"]
        .as_str()
        .unwrap()
        .to_string();
    let dp_sref = idx_val["provenance.r5e.io/v2/DefinitionPublished"]
        .as_str()
        .unwrap()
        .to_string();

    let (custom_def_ref, custom_def_blob) = make_blob(&json!({
        "format": "r5e.kind-definition/v1",
        "kind": "acme.example/v1/Note",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"msg": {"type": "string", "maxLength": 64}}
        }
    }));

    let defs_mixed = vec![
        json!({"kind": "provenance.r5e.io/v2/ChainStarted", "definition": cs_sref}),
        json!({"kind": "provenance.r5e.io/v2/DefinitionPublished", "definition": dp_sref}),
        json!({"kind": "acme.example/v1/Note", "definition": custom_def_ref}),
    ];

    let dummy_prof_ref = bytes_ref_of(b"p");
    let (p_ref, p_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": dp_sref,
            "profileRef": dummy_prof_ref,
            "issuer": pub_key.keyid,
            "actor": "actor:pub",
            "stream": "urn:r5e:stream:pub:1",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T11:00:00Z",
            "body": {"definitions": defs_mixed}
        }),
        &[&pub_key],
    );
    let (cs_ref, cs_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": cs_sref,
            "profileRef": dummy_prof_ref,
            "issuer": boot.keyid,
            "actor": "actor:boot",
            "stream": "urn:r5e:stream:d10:start",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T11:01:00Z",
            "body": {
                "deployment": "d10",
                "bootstrap": boot.keyid,
                "bootstrapKey": {"algorithm": "ed25519", "bytes": STANDARD.encode(boot.pk)},
                "publication": p_ref,
                "publisher": pub_key.keyid,
                "definitions": defs_mixed
            }
        }),
        &[&boot],
    );

    let bundle = empty_bundle_with(
        vec![p_rec, cs_rec],
        vec![custom_def_blob],
        vec![pub_key.key_json(), boot.key_json()],
        vec![],
        vec![],
    );
    let bundle_bytes = encode_canonical_json(&bundle).unwrap().into_bytes();

    // 1. Publisher believed ONLY about `r5e.io` -> `DefinitionPublished` lists `acme.example/v1/Note`
    //    outside `r5e.io`, so BOTH `DefinitionPublished` (`about = p_ref`) AND `ChainStarted` (`about = p_ref`)
    //    get `incomplete / publisher_not_trusted`!
    let mut opts_r5e_only = VerifyOptions::default();
    opts_r5e_only
        .add_trusted_publisher(format!("{}=r5e.io", pub_key.keyid))
        .unwrap();
    let rep_partial = verify_bundle_bytes(&bundle_bytes, &opts_r5e_only).unwrap();
    let dp_pub_partial = rep_partial
        .findings
        .iter()
        .find(|f| f.subject == p_ref && f.check == "publication")
        .unwrap();
    assert_eq!(
        (
            &dp_pub_partial.result[..],
            &dp_pub_partial.code[..],
            dp_pub_partial.about.as_deref()
        ),
        ("incomplete", "publisher_not_trusted", Some(p_ref.as_str()))
    );
    let cs_pub_partial = rep_partial
        .findings
        .iter()
        .find(|f| f.subject == cs_ref && f.check == "publication")
        .unwrap();
    assert_eq!(
        (&cs_pub_partial.result[..], &cs_pub_partial.code[..]),
        ("incomplete", "publisher_not_trusted")
    );

    // 2. Repeated key id union (`pub=r5e.io` + `pub=example`) covers `provenance.r5e.io` AND `acme.example` -> `ChainStarted` is `ok`!
    //    Test via WASM FFI `verify_v2_ffi_bytes` AND CLI `--publisher`!
    let ffi_opts = serde_json::to_vec(&json!({
        "publishers": [
            format!("{}=r5e.io", pub_key.keyid),
            format!("{}=example", pub_key.keyid)
        ]
    }))
    .unwrap();
    let ffi_out: Value = serde_json::from_slice(
        &r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes(&bundle_bytes, &ffi_opts),
    )
    .unwrap();
    assert_eq!(ffi_out["ok"], json!(true));
    let cs_pub_union = ffi_out["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["subject"] == cs_ref && f["check"] == "publication")
        .unwrap();
    assert_eq!(cs_pub_union["result"], json!("ok"));

    // 3. Invalid publisher spec in WASM FFI and CLI exits with code 2!
    let bad_ffi_out: Value = serde_json::from_slice(
        &r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes(
            &bundle_bytes,
            &serde_json::to_vec(&json!({"publishers": [format!("{}=", pub_key.keyid)]})).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(bad_ffi_out["ok"], json!(false));
    assert_eq!(bad_ffi_out["exitCode"], json!(2));

    let tmp = TempDir::new();
    let bpath = tmp.0.join("bundle.json");
    fs::write(&bpath, &bundle_bytes).unwrap();
    let bin = env!("CARGO_BIN_EXE_recurse_verify");
    let ok_cli = Command::new(bin)
        .arg(&bpath)
        .arg("--publisher")
        .arg(format!("{}=r5e.io", pub_key.keyid))
        .arg("--publisher")
        .arg(format!("{}=example", pub_key.keyid))
        .arg("--allow-incomplete")
        .output()
        .unwrap();
    assert_eq!(ok_cli.status.code(), Some(0));

    let bad_cli = Command::new(bin)
        .arg(&bpath)
        .arg("--publisher")
        .arg(format!("{}=", pub_key.keyid))
        .output()
        .unwrap();
    assert_eq!(bad_cli.status.code(), Some(2));
}

#[test]
fn a9_seal_ranges_overlap_precedence_lowest_ref_and_coverage_exclusion() {
    let root = TestKey::from_seed(245);
    let actor_key = TestKey::from_seed(246);
    let sealer = TestKey::from_seed(247);

    let idx_val: Value = serde_json::from_slice(include_bytes!(
        "../vendor/provenance-v2/definitions/index.json"
    ))
    .unwrap();
    let obs_sref = idx_val["provenance.r5e.io/v2/Observation"]
        .as_str()
        .unwrap()
        .to_string();
    let end_sref = idx_val["provenance.r5e.io/v2/Endorsement"]
        .as_str()
        .unwrap()
        .to_string();
    let rev_sref = idx_val["provenance.r5e.io/v2/Revocation"]
        .as_str()
        .unwrap()
        .to_string();
    let seal_sref = idx_val["provenance.r5e.io/v2/EpochSeal"]
        .as_str()
        .unwrap()
        .to_string();

    let (prof_ref, prof_blob) = make_retention_profile(
        json!({
            "provenance.r5e.io/v2/Observation": obs_sref,
            "provenance.r5e.io/v2/Endorsement": end_sref,
            "provenance.r5e.io/v2/Revocation": rev_sref,
            "provenance.r5e.io/v2/EpochSeal": seal_sref,
        }),
        "urn:r5e:stream:dov:",
        &[&root.keyid, &actor_key.keyid, &sealer.keyid],
        &[&sealer.keyid],
        None,
    );

    let (end_actor_ref, end_actor_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:dov:id",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T09:00:00Z",
            "body": {
                "subject": actor_key.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": false,
                "notBefore": "2026-11-15T09:00:00Z",
                "notAfter": "2026-11-15T18:00:00Z"
            }
        }),
        &[&root],
    );
    let (_, end_sealer_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": end_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:dov:id",
            "seq": 2,
            "previous": end_actor_ref,
            "capturedAt": "2026-11-15T09:00:01Z",
            "body": {
                "subject": sealer.keyid,
                "kinds": ["provenance.r5e.io/v2/EpochSeal"],
                "mayEndorse": false,
                "notBefore": "2026-11-15T09:00:00Z",
                "notAfter": "2026-11-15T18:00:00Z"
            }
        }),
        &[&root],
    );

    let mk_obs = |seq: i64, prev: Value| {
        make_signed_record(
            &json!({
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_sref,
                "profileRef": prof_ref,
                "issuer": actor_key.keyid,
                "actor": "actor:rec",
                "stream": "urn:r5e:stream:dov:work",
                "seq": seq,
                "previous": prev,
                "capturedAt": format!("2026-11-15T10:00:0{seq}Z"),
                "body": {"topic": "audit.item", "contentRefs": []}
            }),
            &[&actor_key],
        )
    };
    let (o1_ref, o1_rec) = mk_obs(1, Value::Null);
    let (o2_ref, o2_rec) = mk_obs(2, json!(o1_ref));
    let (o3_ref, o3_rec) = mk_obs(3, json!(o2_ref));
    let (o4_ref, o4_rec) = mk_obs(4, json!(o3_ref));

    let (rev_ref, rev_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": rev_sref,
            "profileRef": prof_ref,
            "issuer": root.keyid,
            "actor": "actor:root",
            "stream": "urn:r5e:stream:dov:rev",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T12:00:00Z",
            "body": {"target": end_actor_ref, "reason": "retired"}
        }),
        &[&root],
    );

    // Seal A: 1..2 (no previousSeal -> pred None)
    let (s_1_2_ref, s_1_2_rec, m_1_2_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:dov:seals",
        "urn:r5e:stream:dov:work",
        1,
        2,
        "2026-11-15T10:01:00Z",
        &[&o1_ref, &o2_ref],
    );

    // Seal B: 3..4 naming `s_1_2_ref` (pred `ok`, about `s_1_2_ref`)
    let d3 = digest_of(&o3_ref);
    let d4 = digest_of(&o4_ref);
    let r_3_4 = format!("sha256:{}", hex_encode(&merkle_root(&[d3, d4])));
    let (m_3_4_ref, m_3_4_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [o3_ref, o4_ref]
    }));
    let (s_3_4_ref, s_3_4_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "urn:r5e:stream:dov:seals",
            "seq": 2,
            "previous": s_1_2_ref,
            "capturedAt": "2026-11-15T10:02:00Z",
            "body": {
                "stream": "urn:r5e:stream:dov:work",
                "firstSeq": 3,
                "lastSeq": 4,
                "previousSeal": s_1_2_ref,
                "root": r_3_4,
                "manifestRef": m_3_4_ref
            }
        }),
        &[&sealer],
    );

    // Seal C: 1..4 (no previousSeal -> pred None; overlaps BOTH `s_1_2_ref` AND `s_3_4_ref`!)
    let (s_1_4_ref, s_1_4_rec, m_1_4_blob) = make_seal_over_events(
        &seal_sref,
        &prof_ref,
        &sealer,
        "urn:r5e:stream:dov:seals-alt",
        "urn:r5e:stream:dov:work",
        1,
        4,
        "2026-11-15T10:03:00Z",
        &[&o1_ref, &o2_ref, &o3_ref, &o4_ref],
    );

    // Seal D: 2..2 with NO previousSeal -> pred `failed / seal_predecessor_missing` (must NOT be replaced by overlap!)
    let d2 = digest_of(&o2_ref);
    let r_2_2 = format!("sha256:{}", hex_encode(&merkle_root(&[d2])));
    let (m_2_2_ref, m_2_2_blob) = make_blob(&json!({
        "format": "r5e.provenance-epoch/v2",
        "events": [o2_ref]
    }));
    let (s_2_2_bad_pred_ref, s_2_2_bad_pred_rec) = make_signed_record(
        &json!({
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "EpochSeal",
            "schemaRef": seal_sref,
            "profileRef": prof_ref,
            "issuer": sealer.keyid,
            "actor": "actor:sealer",
            "stream": "urn:r5e:stream:dov:seals-bad",
            "seq": 1,
            "previous": null,
            "capturedAt": "2026-11-15T10:04:00Z",
            "body": {
                "stream": "urn:r5e:stream:dov:work",
                "firstSeq": 2,
                "lastSeq": 2,
                "root": r_2_2,
                "manifestRef": m_2_2_ref
            }
        }),
        &[&sealer],
    );

    let mut opts = VerifyOptions::default();
    opts.trusted_roots = Some([root.keyid.clone()].into_iter().collect());

    let rep = verify_bundle_value(
        &empty_bundle_with(
            vec![
                end_actor_rec,
                end_sealer_rec,
                o1_rec,
                o2_rec,
                o3_rec,
                o4_rec,
                rev_rec,
                s_1_2_rec,
                s_3_4_rec,
                s_1_4_rec,
                s_2_2_bad_pred_rec,
            ],
            vec![prof_blob, m_1_2_blob, m_3_4_blob, m_1_4_blob, m_2_2_blob],
            vec![root.key_json(), actor_key.key_json(), sealer.key_json()],
            vec![
                json!(s_1_2_ref),
                json!(s_3_4_ref),
                json!(s_1_4_ref),
                json!(s_2_2_bad_pred_ref),
            ],
            vec![],
        ),
        &opts,
    );

    // Exactly ONE `seal_chain` finding per seal:
    for sr in [&s_1_2_ref, &s_3_4_ref, &s_1_4_ref, &s_2_2_bad_pred_ref] {
        let count = rep
            .findings
            .iter()
            .filter(|f| f.layer == 3 && f.subject == *sr && f.check == "seal_chain")
            .count();
        assert_eq!(count, 1, "expected exactly 1 seal_chain finding on {sr}");
    }

    // `s_2_2_bad_pred_ref` keeps its predecessor failure (`seal_predecessor_missing`, `about: None`):
    let f_bad_pred = rep
        .findings
        .iter()
        .find(|f| f.layer == 3 && f.subject == s_2_2_bad_pred_ref && f.check == "seal_chain")
        .unwrap();
    assert_eq!(
        (
            &f_bad_pred.result[..],
            &f_bad_pred.code[..],
            f_bad_pred.about.as_deref()
        ),
        ("failed", "seal_predecessor_missing", None)
    );

    // `s_3_4_ref` had predecessor `ok`, which is REPLACED by `seal_ranges_overlap` (`about = s_1_4_ref`)!
    let f_3_4 = rep
        .findings
        .iter()
        .find(|f| f.layer == 3 && f.subject == s_3_4_ref && f.check == "seal_chain")
        .unwrap();
    assert_eq!(
        (&f_3_4.result[..], &f_3_4.code[..], f_3_4.about.as_deref()),
        ("failed", "seal_ranges_overlap", Some(s_1_4_ref.as_str()))
    );

    // `s_1_4_ref` overlaps `s_1_2_ref`, `s_3_4_ref`, and `s_2_2_bad_pred_ref`: `about` is the lowest ref in byte order!
    let expected_min_for_1_4 = [
        s_1_2_ref.as_str(),
        s_3_4_ref.as_str(),
        s_2_2_bad_pred_ref.as_str(),
    ]
    .into_iter()
    .min_by(|a, b| a.as_bytes().cmp(b.as_bytes()))
    .unwrap();
    let f_1_4 = rep
        .findings
        .iter()
        .find(|f| f.layer == 3 && f.subject == s_1_4_ref && f.check == "seal_chain")
        .unwrap();
    assert_eq!(
        (&f_1_4.result[..], &f_1_4.code[..], f_1_4.about.as_deref()),
        ("failed", "seal_ranges_overlap", Some(expected_min_for_1_4))
    );

    // All four seals failed `seal_chain`, so NONE fixes `o1..o4` in time before `rev_ref`:
    for obs_r in [&o1_ref, &o2_ref, &o3_ref, &o4_ref] {
        let auth_f = find_authority_finding(&rep, obs_r).unwrap();
        assert_eq!(
            (
                &auth_f.result[..],
                &auth_f.code[..],
                auth_f.about.as_deref()
            ),
            (
                "incomplete",
                "time_rests_on_the_signer",
                Some(rev_ref.as_str())
            )
        );
    }
}
