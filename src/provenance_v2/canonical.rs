use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_SAFE_INT: i64 = 9_007_199_254_740_991; // 2^53 - 1
pub const MIN_SAFE_INT: i64 = -9_007_199_254_740_991; // -(2^53 - 1)

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn decode_hex_32(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    if !hex_str
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn is_bytes_ref(s: &str) -> bool {
    s.strip_prefix("bytes:sha256:").is_some_and(is_lower_hex_64)
}

pub fn is_salted_bytes_ref(s: &str) -> bool {
    s.strip_prefix("bytes:sha256+salt:")
        .is_some_and(is_lower_hex_64)
}

pub fn is_event_ref(s: &str) -> bool {
    s.strip_prefix("event:sha256:").is_some_and(is_lower_hex_64)
}

pub fn is_evidence_ref(s: &str) -> bool {
    s.strip_prefix("evidence:sha256:")
        .is_some_and(is_lower_hex_64)
}

pub fn bytes_ref_of(data: &[u8]) -> String {
    format!("bytes:sha256:{}", hex_encode(&sha256_bytes(data)))
}

pub fn salted_bytes_ref_of(salt: &[u8], plaintext: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"r5e-salted-content-v1\0");
    hasher.update(salt);
    hasher.update(plaintext);
    let digest: [u8; 32] = hasher.finalize().into();
    format!("bytes:sha256+salt:{}", hex_encode(&digest))
}

pub fn evidence_ref_of(payload_bytes: &[u8]) -> String {
    format!(
        "evidence:sha256:{}",
        hex_encode(&sha256_bytes(payload_bytes))
    )
}

/// §2.5 standard padded base64 (may decode to zero bytes, e.g. empty blob).
/// Requires canonical zero pad bits (`STANDARD.encode(&b) == s`).
pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(s).ok()?;
    if STANDARD.encode(&bytes) == s {
        Some(bytes)
    } else {
        None
    }
}

/// §2.5 strict base64: standard padded encoding of at least one byte,
/// whose re-encoding equals `s`.
pub fn decode_strict_base64(s: &str) -> Option<Vec<u8>> {
    let bytes = decode_base64(s)?;
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// §2.1 / §2.8 integer domain: integer with no fraction, exponent, or `-0`,
/// within `-(2^53 - 1) ..= (2^53 - 1)`.
pub fn parse_v2_integer(v: &Value) -> Option<i64> {
    let n = v.as_number()?;
    let s = n.to_string();
    if s == "-0" || s.contains(['.', 'e', 'E']) {
        return None;
    }
    let val: i64 = s.parse().ok()?;
    if (MIN_SAFE_INT..=MAX_SAFE_INT).contains(&val) {
        Some(val)
    } else {
        None
    }
}

pub fn encode_canonical_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x09' => out.push_str("\\t"),
            '\x0a' => out.push_str("\\n"),
            '\x0c' => out.push_str("\\f"),
            '\x0d' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// §2.1 Canonical JSON encoder (RFC 8785 JCS over the restricted Provenance v2 domain).
pub fn encode_canonical_json(v: &Value) -> Option<String> {
    match v {
        Value::Null => Some("null".to_string()),
        Value::Bool(true) => Some("true".to_string()),
        Value::Bool(false) => Some("false".to_string()),
        Value::Number(_) => {
            let i = parse_v2_integer(v)?;
            Some(i.to_string())
        }
        Value::String(s) => Some(encode_canonical_string(s)),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(encode_canonical_json(item)?);
            }
            Some(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            let mut entries: Vec<(&str, &Value)> = Vec::with_capacity(map.len());
            for (k, val) in map {
                if k.chars().any(|c| (c as u32) > 0xFFFF) {
                    return None;
                }
                entries.push((k.as_str(), val));
            }
            entries.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            let mut parts = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                parts.push(format!(
                    "{}:{}",
                    encode_canonical_string(k),
                    encode_canonical_json(val)?
                ));
            }
            Some(format!("{{{}}}", parts.join(",")))
        }
    }
}

/// §3 Outer JSON parser: valid UTF-8, RFC 8259, with no repeated key anywhere.
/// Numbers outside the §2.1 domain (`-0`, fractions, integers beyond `±(2^53 - 1)`)
/// are preserved via `serde_json` `arbitrary_precision` so schema/canonical checks decide.
pub fn strict_json_parse(bytes: &[u8]) -> Option<Value> {
    let decoded: Value = serde_json::from_slice(bytes).ok()?;
    struct Scanner<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl Scanner<'_> {
        fn skip_ws(&mut self) {
            while self
                .b
                .get(self.i)
                .is_some_and(|c| matches!(c, b' ' | b'\n' | b'\r' | b'\t'))
            {
                self.i += 1;
            }
        }
        fn scan_string(&mut self) -> Option<String> {
            let start = self.i;
            if self.b.get(self.i) != Some(&b'"') {
                return None;
            }
            self.i += 1;
            loop {
                let c = *self.b.get(self.i)?;
                self.i += 1;
                if c == b'"' {
                    break;
                }
                if c == b'\\' {
                    let _esc = *self.b.get(self.i)?;
                    self.i += 1;
                } else if c < 0x20 {
                    return None;
                }
            }
            serde_json::from_slice(self.b.get(start..self.i)?).ok()
        }
        fn scan_value(&mut self) -> Option<()> {
            self.skip_ws();
            match *self.b.get(self.i)? {
                b'{' => {
                    self.i += 1;
                    self.skip_ws();
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Some(());
                    }
                    let mut keys = BTreeSet::new();
                    loop {
                        let k = self.scan_string()?;
                        if !keys.insert(k) {
                            return None;
                        }
                        self.skip_ws();
                        if self.b.get(self.i) != Some(&b':') {
                            return None;
                        }
                        self.i += 1;
                        self.scan_value()?;
                        self.skip_ws();
                        match self.b.get(self.i)? {
                            b'}' => {
                                self.i += 1;
                                break;
                            }
                            b',' => {
                                self.i += 1;
                                self.skip_ws();
                            }
                            _ => return None,
                        }
                    }
                }
                b'[' => {
                    self.i += 1;
                    self.skip_ws();
                    if self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Some(());
                    }
                    loop {
                        self.scan_value()?;
                        self.skip_ws();
                        match self.b.get(self.i)? {
                            b']' => {
                                self.i += 1;
                                break;
                            }
                            b',' => {
                                self.i += 1;
                            }
                            _ => return None,
                        }
                    }
                }
                b'"' => {
                    self.scan_string()?;
                }
                b'-' | b'0'..=b'9' => {
                    while self
                        .b
                        .get(self.i)
                        .is_some_and(|c| b"-+0123456789.eE".contains(c))
                    {
                        self.i += 1;
                    }
                }
                b't' => {
                    if self.b.get(self.i..self.i + 4) != Some(b"true") {
                        return None;
                    }
                    self.i += 4;
                }
                b'f' => {
                    if self.b.get(self.i..self.i + 5) != Some(b"false") {
                        return None;
                    }
                    self.i += 5;
                }
                b'n' => {
                    if self.b.get(self.i..self.i + 4) != Some(b"null") {
                        return None;
                    }
                    self.i += 4;
                }
                _ => return None,
            }
            Some(())
        }
    }
    let mut scanner = Scanner { b: bytes, i: 0 };
    scanner.scan_value()?;
    scanner.skip_ws();
    if scanner.i != bytes.len() {
        return None;
    }
    Some(decoded)
}

/// §2.1 Canonical JSON byte check: parses under the restricted rules and
/// re-encoding produces the exact input bytes.
pub fn parse_canonical_json(bytes: &[u8]) -> Option<Value> {
    let val = strict_json_parse(bytes)?;
    let encoded = encode_canonical_json(&val)?;
    if encoded.as_bytes() == bytes {
        Some(val)
    } else {
        None
    }
}

/// Exact UTC instant parsed from an RFC 3339 timestamp, with arbitrary-length
/// normalized fractional seconds (trailing zeros stripped) so comparisons are exact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcInstant {
    pub utc_seconds: i64,
    pub norm_frac: String,
}

impl UtcInstant {
    /// Exact UTC epoch nanoseconds (`instant_ns` in `A7` §§4–5) as a 128-bit signed integer.
    pub fn to_epoch_ns(&self) -> i128 {
        let mut nanos: i128 = 0;
        let frac_bytes = self.norm_frac.as_bytes();
        for i in 0..9 {
            let d = frac_bytes.get(i).map(|&b| (b - b'0') as i128).unwrap_or(0);
            nanos = nanos * 10 + d;
        }
        (self.utc_seconds as i128) * 1_000_000_000 + nanos
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let d = d as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i64) - 719_468
}

fn parse_digits_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Parses `YYYY-MM-DDThh:mm:ss(\.[0-9]+)?(Z|[+-]hh:mm)` (uppercase `T` and `Z`
/// unless `allow_lowercase_tz` is set) and validates real calendar date & time.
pub fn parse_rfc3339_instant(
    s: &str,
    max_frac_digits: Option<usize>,
    allow_lowercase_tz: bool,
) -> Option<UtcInstant> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let t_sep = b[10];
    if !(t_sep == b'T' || (allow_lowercase_tz && t_sep == b't')) {
        return None;
    }
    let year = parse_digits_u32(&b[0..4])? as i32;
    let month = parse_digits_u32(&b[5..7])?;
    let day = parse_digits_u32(&b[8..10])?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return None;
    }
    let hour = parse_digits_u32(&b[11..13])?;
    let minute = parse_digits_u32(&b[14..16])?;
    let second = parse_digits_u32(&b[17..19])?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut pos = 19;
    let mut norm_frac = String::new();
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        let frac_start = pos;
        while b.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        let frac_len = pos - frac_start;
        if frac_len == 0 {
            return None;
        }
        if let Some(max_d) = max_frac_digits
            && frac_len > max_d
        {
            return None;
        }
        let frac_str = std::str::from_utf8(&b[frac_start..pos]).ok()?;
        norm_frac = frac_str.trim_end_matches('0').to_string();
    }

    let rem = &b[pos..];
    let offset_seconds: i64 = if rem == b"Z" || (allow_lowercase_tz && rem == b"z") {
        0
    } else if rem.len() == 6 && (rem[0] == b'+' || rem[0] == b'-') && rem[3] == b':' {
        let off_h = parse_digits_u32(&rem[1..3])?;
        let off_m = parse_digits_u32(&rem[4..6])?;
        if off_h > 23 || off_m > 59 {
            return None;
        }
        let mag = (off_h as i64) * 3600 + (off_m as i64) * 60;
        if rem[0] == b'+' { mag } else { -mag }
    } else {
        return None;
    };

    let days = days_from_civil(year as i64, month, day);
    let local_seconds =
        days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
    let utc_seconds = local_seconds - offset_seconds;
    Some(UtcInstant {
        utc_seconds,
        norm_frac,
    })
}

/// §2.7 `format: date-time` check: `YYYY-MM-DDThh:mm:ss`, optional fraction, then `Z` or numeric offset.
pub fn is_valid_wire_datetime(s: &str) -> bool {
    parse_rfc3339_instant(s, None, false).is_some()
}

pub fn is_valid_utc_z_datetime(s: &str) -> bool {
    s.ends_with('Z') && parse_rfc3339_instant(s, None, false).is_some()
}

/// Fixed-time byte slice equality check for cryptographic digests and key IDs.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

/// Fixed-time string equality check for cryptographic digests and key IDs.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}
