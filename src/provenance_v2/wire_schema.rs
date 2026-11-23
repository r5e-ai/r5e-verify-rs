use super::canonical::{
    is_bytes_ref, is_evidence_ref, is_lower_hex_64, is_salted_bytes_ref, is_valid_utc_z_datetime,
    is_valid_wire_datetime, parse_v2_integer,
};
use serde_json::Value;
use std::sync::LazyLock;

static EXPORT_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../vendor/provenance-v2/schemas/export.schema.json"
    ))
    .expect("embedded export.schema.json must be valid JSON")
});

static SIGNED_EVIDENCE_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../vendor/provenance-v2/schemas/signed-evidence.schema.json"
    ))
    .expect("embedded signed-evidence.schema.json must be valid JSON")
});

static EVIDENCE_ENVELOPE_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../vendor/provenance-v2/schemas/evidence-envelope.schema.json"
    ))
    .expect("embedded evidence-envelope.schema.json must be valid JSON")
});

static CAPTURE_PROFILE_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../vendor/provenance-v2/schemas/capture-profile.schema.json"
    ))
    .expect("embedded capture-profile.schema.json must be valid JSON")
});

static EPOCH_MANIFEST_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../vendor/provenance-v2/schemas/epoch-manifest.schema.json"
    ))
    .expect("embedded epoch-manifest.schema.json must be valid JSON")
});

#[derive(Debug, Clone, Copy)]
pub enum WireSchemaKind {
    Export,
    SignedEvidence,
    EvidenceEnvelope,
    CaptureProfile,
    EpochManifest,
}

pub fn validate_wire_schema(kind: WireSchemaKind, instance: &Value) -> bool {
    let root = match kind {
        WireSchemaKind::Export => &*EXPORT_SCHEMA,
        WireSchemaKind::SignedEvidence => &*SIGNED_EVIDENCE_SCHEMA,
        WireSchemaKind::EvidenceEnvelope => &*EVIDENCE_ENVELOPE_SCHEMA,
        WireSchemaKind::CaptureProfile => &*CAPTURE_PROFILE_SCHEMA,
        WireSchemaKind::EpochManifest => &*EPOCH_MANIFEST_SCHEMA,
    };
    validate_against_schema(root, instance)
}

/// Validates an export bundle in Amendment A11 mode: validates optional A11
/// top-level members in full detail and validates all remaining top-level
/// members against `export.schema.json` without cloning the bundle.
pub fn validate_a11_export_schema(instance: &Value) -> bool {
    let Some(obj) = instance.as_object() else {
        return false;
    };
    if let Some(sc) = obj.get("saltedContent")
        && !validate_salted_content_member(sc)
    {
        return false;
    }
    if let Some(wr) = obj.get("witnessReceipts")
        && !validate_witness_receipts_member(wr)
    {
        return false;
    }
    if let Some(ul) = obj.get("unlockLog")
        && !validate_unlock_log_member(ul)
    {
        return false;
    }
    if let Some(pc) = obj.get("pinnedCheckpoints")
        && !validate_pinned_checkpoints_member(pc)
    {
        return false;
    }
    validate_node_with_skip(
        &EXPORT_SCHEMA,
        &EXPORT_SCHEMA,
        instance,
        &A11_EXPORT_MEMBERS,
    )
}

pub const A11_EXPORT_MEMBERS: [&str; 4] = [
    "saltedContent",
    "witnessReceipts",
    "unlockLog",
    "pinnedCheckpoints",
];

fn is_sha256_prefixed(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(is_lower_hex_64)
}

fn is_key_id_shape(s: &str) -> bool {
    s.starts_with("key:") && s.len() > 4
}

fn validate_salted_content_member(v: &Value) -> bool {
    let Some(map) = v.as_object() else {
        return false;
    };
    for (k, entry) in map {
        if !is_salted_bytes_ref(k) {
            return false;
        }
        let Some(eobj) = entry.as_object() else {
            return false;
        };
        if eobj.len() != 2 {
            return false;
        }
        if !eobj.get("salt").is_some_and(Value::is_string)
            || !eobj.get("bytes").is_some_and(Value::is_string)
        {
            return false;
        }
    }
    true
}

fn validate_witness_receipts_member(v: &Value) -> bool {
    let Some(map) = v.as_object() else {
        return false;
    };
    for (k, entry) in map {
        if !is_bytes_ref(k) {
            return false;
        }
        let Some(eobj) = entry.as_object() else {
            return false;
        };
        if eobj.len() != 6 {
            return false;
        }
        let log_index_ok = eobj
            .get("logIndex")
            .and_then(parse_v2_integer)
            .is_some_and(|n| n >= 0);
        let logged_at_ok = eobj
            .get("loggedAt")
            .and_then(Value::as_str)
            .is_some_and(is_valid_utc_z_datetime);
        let req_hash_ok = eobj
            .get("requestHash")
            .and_then(Value::as_str)
            .is_some_and(is_sha256_prefixed);
        let req_ref_ok = eobj
            .get("requestRef")
            .and_then(Value::as_str)
            .is_some_and(is_evidence_ref);
        let sig_ok = eobj
            .get("signature")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let witness_key_ok = eobj
            .get("witnessKey")
            .and_then(Value::as_str)
            .is_some_and(is_key_id_shape);
        if !log_index_ok
            || !logged_at_ok
            || !req_hash_ok
            || !req_ref_ok
            || !sig_ok
            || !witness_key_ok
        {
            return false;
        }
    }
    true
}

fn validate_unlock_log_member(v: &Value) -> bool {
    let Some(arr) = v.as_array() else {
        return false;
    };
    for entry in arr {
        let Some(eobj) = entry.as_object() else {
            return false;
        };
        if eobj.len() != 5 {
            return false;
        }
        let entry_id_ok = eobj
            .get("entryId")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let operator_key_ok = eobj
            .get("operatorKey")
            .and_then(Value::as_str)
            .is_some_and(is_key_id_shape);
        let release_ref_ok = eobj
            .get("releaseRef")
            .is_some_and(|rv| rv.is_null() || rv.as_str().is_some_and(is_evidence_ref));
        let session_ok = eobj
            .get("session")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let unlocked_at_ok = eobj
            .get("unlockedAt")
            .and_then(Value::as_str)
            .is_some_and(is_valid_utc_z_datetime);
        if !entry_id_ok || !operator_key_ok || !release_ref_ok || !session_ok || !unlocked_at_ok {
            return false;
        }
    }
    true
}

fn validate_pinned_checkpoints_member(v: &Value) -> bool {
    let Some(arr) = v.as_array() else {
        return false;
    };
    for entry in arr {
        let Some(eobj) = entry.as_object() else {
            return false;
        };
        if eobj.len() != 2 {
            return false;
        }
        let ref_ok = eobj
            .get("ref")
            .and_then(Value::as_str)
            .is_some_and(is_evidence_ref);
        let seq_ok = eobj
            .get("seq")
            .and_then(parse_v2_integer)
            .is_some_and(|n| n >= 1);
        if !ref_ok || !seq_ok {
            return false;
        }
    }
    true
}

pub fn validate_against_schema(root: &Value, instance: &Value) -> bool {
    validate_node_with_skip(root, root, instance, &[])
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if reference == "#" {
        return Some(root);
    }
    let pointer = reference.strip_prefix("#/")?;
    let mut cur = root;
    for raw_seg in pointer.split('/') {
        let seg = raw_seg.replace("~1", "/").replace("~0", "~");
        match cur {
            Value::Object(map) => {
                cur = map.get(&seg)?;
            }
            Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                cur = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn matches_wire_type(type_name: &str, v: &Value) -> bool {
    match type_name {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "integer" => parse_v2_integer(v).is_some(),
        "string" => v.is_string(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        _ => false,
    }
}

pub fn matches_wire_pattern(pattern: &str, text: &str) -> bool {
    // Neither `regex` nor `fancy-regex` sets multi-line mode by default, so `$`
    // matches only at the end of the whole string and never before a trailing `\n`.
    if let Ok(re) = regex::Regex::new(pattern) {
        return re.is_match(text);
    }
    if let Ok(re) = fancy_regex::Regex::new(pattern) {
        return re.is_match(text).unwrap_or(false);
    }
    false
}

fn validate_node(root: &Value, schema: &Value, instance: &Value) -> bool {
    validate_node_with_skip(root, schema, instance, &[])
}

fn validate_node_with_skip(
    root: &Value,
    schema: &Value,
    instance: &Value,
    skip_top_keys: &[&str],
) -> bool {
    if let Value::Bool(b) = schema {
        return *b;
    }
    let Some(smap) = schema.as_object() else {
        return false;
    };

    if let Some(ref_val) = smap.get("$ref") {
        let Some(ref_str) = ref_val.as_str() else {
            return false;
        };
        let Some(target) = resolve_local_ref(root, ref_str) else {
            return false;
        };
        if !validate_node_with_skip(root, target, instance, skip_top_keys) {
            return false;
        }
    }

    if let Some(type_val) = smap.get("type") {
        let ok = match type_val {
            Value::String(t) => matches_wire_type(t, instance),
            Value::Array(ts) => ts
                .iter()
                .any(|t| t.as_str().is_some_and(|s| matches_wire_type(s, instance))),
            _ => false,
        };
        if !ok {
            return false;
        }
    }

    if let Some(const_val) = smap.get("const")
        && instance != const_val
    {
        return false;
    }

    if let Some(enum_val) = smap.get("enum") {
        let Some(arr) = enum_val.as_array() else {
            return false;
        };
        if !arr.iter().any(|item| item == instance) {
            return false;
        }
    }

    if let Some(all_of) = smap.get("allOf") {
        let Some(arr) = all_of.as_array() else {
            return false;
        };
        if !arr
            .iter()
            .all(|sub| validate_node_with_skip(root, sub, instance, skip_top_keys))
        {
            return false;
        }
    }

    if let Some(any_of) = smap.get("anyOf") {
        let Some(arr) = any_of.as_array() else {
            return false;
        };
        if !arr
            .iter()
            .any(|sub| validate_node_with_skip(root, sub, instance, skip_top_keys))
        {
            return false;
        }
    }

    if let Some(one_of) = smap.get("oneOf") {
        let Some(arr) = one_of.as_array() else {
            return false;
        };
        let matches = arr
            .iter()
            .filter(|sub| validate_node_with_skip(root, sub, instance, skip_top_keys))
            .count();
        if matches != 1 {
            return false;
        }
    }

    if let Some(if_schema) = smap.get("if") {
        if validate_node_with_skip(root, if_schema, instance, skip_top_keys) {
            if let Some(then_schema) = smap.get("then")
                && !validate_node_with_skip(root, then_schema, instance, skip_top_keys)
            {
                return false;
            }
        } else if let Some(else_schema) = smap.get("else")
            && !validate_node_with_skip(root, else_schema, instance, skip_top_keys)
        {
            return false;
        }
    }

    if let Value::String(s) = instance {
        if let Some(min_len_val) = smap.get("minLength") {
            let Some(min_len) = parse_v2_integer(min_len_val) else {
                return false;
            };
            if min_len > 0 && (s.chars().count() as i64) < min_len {
                return false;
            }
        }
        if let Some(pat_val) = smap.get("pattern") {
            let Some(pat) = pat_val.as_str() else {
                return false;
            };
            if !matches_wire_pattern(pat, s) {
                return false;
            }
        }
        if let Some(fmt_val) = smap.get("format")
            && fmt_val.as_str() == Some("date-time")
            && !is_valid_wire_datetime(s)
        {
            return false;
        }
    }

    if let Some(int_val) = parse_v2_integer(instance)
        && let Some(min_val) = smap.get("minimum")
    {
        let Some(min_i) = parse_v2_integer(min_val) else {
            return false;
        };
        if int_val < min_i {
            return false;
        }
    }

    if let Value::Array(items_arr) = instance {
        if let Some(min_items_val) = smap.get("minItems") {
            let Some(min_items) = parse_v2_integer(min_items_val) else {
                return false;
            };
            if min_items > 0 && (items_arr.len() as i64) < min_items {
                return false;
            }
        }
        if let Some(max_items_val) = smap.get("maxItems") {
            let Some(max_items) = parse_v2_integer(max_items_val) else {
                return false;
            };
            if max_items < 0 || (items_arr.len() as i64) > max_items {
                return false;
            }
        }
        if let Some(items_schema) = smap.get("items") {
            for item in items_arr {
                if !validate_node(root, items_schema, item) {
                    return false;
                }
            }
        }
        if smap.get("uniqueItems") == Some(&Value::Bool(true)) {
            for i in 0..items_arr.len() {
                for j in (i + 1)..items_arr.len() {
                    if items_arr[i] == items_arr[j] {
                        return false;
                    }
                }
            }
        }
    }

    if let Value::Object(obj) = instance {
        if let Some(min_props_val) = smap.get("minProperties") {
            let Some(min_props) = parse_v2_integer(min_props_val) else {
                return false;
            };
            let effective_len = if skip_top_keys.is_empty() {
                obj.len()
            } else {
                obj.keys()
                    .filter(|k| !skip_top_keys.contains(&k.as_str()))
                    .count()
            };
            if min_props > 0 && (effective_len as i64) < min_props {
                return false;
            }
        }
        if let Some(req_val) = smap.get("required") {
            let Some(req_arr) = req_val.as_array() else {
                return false;
            };
            for req_key in req_arr {
                let Some(k) = req_key.as_str() else {
                    return false;
                };
                if !obj.contains_key(k) {
                    return false;
                }
            }
        }
        if let Some(prop_names_schema) = smap.get("propertyNames") {
            for k in obj.keys() {
                if !skip_top_keys.is_empty() && skip_top_keys.contains(&k.as_str()) {
                    continue;
                }
                if !validate_node(root, prop_names_schema, &Value::String(k.clone())) {
                    return false;
                }
            }
        }
        let props_map = smap.get("properties").and_then(Value::as_object);
        if let Some(pmap) = props_map {
            for (k, prop_schema) in pmap {
                if let Some(v) = obj.get(k)
                    && !validate_node(root, prop_schema, v)
                {
                    return false;
                }
            }
        }
        if let Some(addl) = smap.get("additionalProperties") {
            for (k, v) in obj {
                if !skip_top_keys.is_empty() && skip_top_keys.contains(&k.as_str()) {
                    continue;
                }
                let is_declared = props_map.is_some_and(|pm| pm.contains_key(k));
                if !is_declared && !validate_node(root, addl, v) {
                    return false;
                }
            }
        }
    }

    true
}
