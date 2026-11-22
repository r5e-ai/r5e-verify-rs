use super::canonical::{
    decode_strict_base64, encode_canonical_json, is_bytes_ref, is_event_ref, is_evidence_ref,
    parse_canonical_json, parse_rfc3339_instant, parse_v2_integer,
};
use super::crypto::{compute_keyid, is_key_admissible, is_registered_algorithm};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const TIMESTAMP_PATTERN: &str = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$";

const ALLOWED_SCHEMA_KEYS: [&str; 24] = [
    "type",
    "enum",
    "pattern",
    "minimum",
    "maximum",
    "items",
    "properties",
    "additionalProperties",
    "values",
    "required",
    "nonEmpty",
    "ordered",
    "exactlyOne",
    "atMostOne",
    "requires",
    "matchesSigner",
    "keyBytes",
    "derives",
    "ref",
    "description",
    "unique",
    "keys",
    "maxEntries",
    "maxLength",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefType {
    String,
    Integer,
    Boolean,
    Object,
    Array,
    Ref,
}

#[derive(Debug)]
pub struct CompiledBytePattern(CompiledBytePatternInner);

#[derive(Debug)]
enum CompiledBytePatternInner {
    Bytes(regex::bytes::Regex),
    Fancy(fancy_regex::Regex),
}

impl CompiledBytePattern {
    fn compile(pattern: &str) -> Option<Self> {
        if let Ok(re) = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
        {
            return Some(Self(CompiledBytePatternInner::Bytes(re)));
        }
        if let Ok(re) = regex::bytes::Regex::new(pattern) {
            return Some(Self(CompiledBytePatternInner::Bytes(re)));
        }
        if let Ok(re) = fancy_regex::Regex::new(pattern) {
            return Some(Self(CompiledBytePatternInner::Fancy(re)));
        }
        None
    }

    fn is_match(&self, text: &str) -> bool {
        match &self.0 {
            CompiledBytePatternInner::Bytes(re) => re.is_match(text.as_bytes()),
            CompiledBytePatternInner::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RefSpec {
    pub cross_chain: bool,
    pub target: RefTarget,
}

#[derive(Debug, Clone)]
pub enum RefTarget {
    Bytes,
    Evidence,
    Event,
    AnyOf(Vec<RefSpec>),
}

impl RefSpec {
    fn parse(v: &Value) -> Option<Self> {
        let map = v.as_object()?;
        let mut cross_chain = false;
        let mut target: Option<RefTarget> = None;
        for (k, val) in map {
            match k.as_str() {
                "crossChain" => {
                    if val == &Value::Bool(true) {
                        cross_chain = true;
                    } else {
                        return None;
                    }
                }
                "bytes" => {
                    if target.is_some() || val != &Value::Bool(true) {
                        return None;
                    }
                    target = Some(RefTarget::Bytes);
                }
                "evidence" => {
                    if target.is_some() || val != &Value::Bool(true) {
                        return None;
                    }
                    target = Some(RefTarget::Evidence);
                }
                "event" => {
                    if target.is_some() || val == &Value::Bool(false) || val.is_null() {
                        return None;
                    }
                    target = Some(RefTarget::Event);
                }
                "anyOf" => {
                    if target.is_some() {
                        return None;
                    }
                    let arr = val.as_array()?;
                    if arr.is_empty() {
                        return None;
                    }
                    let mut specs = Vec::with_capacity(arr.len());
                    for item in arr {
                        specs.push(Self::parse(item)?);
                    }
                    target = Some(RefTarget::AnyOf(specs));
                }
                _ => return None,
            }
        }
        Some(Self {
            cross_chain,
            target: target?,
        })
    }

    fn matches_direct(&self, s: &str) -> bool {
        match &self.target {
            RefTarget::Bytes => is_bytes_ref(s),
            RefTarget::Evidence => is_evidence_ref(s),
            RefTarget::Event => is_event_ref(s),
            RefTarget::AnyOf(alts) => alts.iter().any(|alt| alt.matches_direct(s)),
        }
    }

    fn matches(&self, s: &str) -> bool {
        if let Some(rest) = s.strip_prefix("chain:") {
            let Some((chain_name, inner_ref)) = rest.split_once('/') else {
                return false;
            };
            if !is_evidence_ref(chain_name) {
                return false;
            }
            if self.cross_chain {
                return self.matches_direct(inner_ref);
            }
            if let RefTarget::AnyOf(alts) = &self.target {
                return alts
                    .iter()
                    .any(|alt| alt.cross_chain && alt.matches_direct(inner_ref));
            }
            false
        } else {
            self.matches_direct(s)
        }
    }
}

#[derive(Debug, Clone)]
pub enum DerivesSpec {
    KeyIdOf(String),
}

#[derive(Debug, Clone)]
pub struct RequiresRule {
    pub when_field: String,
    pub when_equals: Value,
    pub then_fields: Vec<String>,
}

#[derive(Debug)]
pub struct DefNode {
    pub types: Vec<DefType>,
    pub enum_values: Option<Vec<Value>>,
    pub pattern: Option<(CompiledBytePattern, bool)>,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
    pub items: Option<Box<DefNode>>,
    pub properties: BTreeMap<String, DefNode>,
    pub additional_properties_false: bool,
    pub values: Option<Box<DefNode>>,
    pub required: Vec<String>,
    pub non_empty: Vec<String>,
    pub ordered: Vec<(String, String)>,
    pub exactly_one: Vec<Vec<String>>,
    pub at_most_one: Vec<Vec<String>>,
    pub requires: Vec<RequiresRule>,
    pub matches_signer: Option<usize>,
    pub key_bytes: bool,
    pub derives: Option<DerivesSpec>,
    pub ref_spec: Option<RefSpec>,
    pub unique: bool,
    pub keys: Option<CompiledBytePattern>,
    pub max_entries: Option<usize>,
    pub max_length: Option<usize>,
}

impl DefNode {
    fn is_exclusively_type(&self, expected: DefType) -> bool {
        !self.types.is_empty() && self.types.iter().all(|&t| t == expected)
    }

    fn max_signer_referenced(&self) -> usize {
        let mut max_pos = self.matches_signer.unwrap_or(0);
        if let Some(items) = &self.items {
            max_pos = max_pos.max(items.max_signer_referenced());
        }
        if let Some(values) = &self.values {
            max_pos = max_pos.max(values.max_signer_referenced());
        }
        for prop in self.properties.values() {
            max_pos = max_pos.max(prop.max_signer_referenced());
        }
        max_pos
    }
}

#[derive(Debug)]
pub struct ParsedDefinition {
    pub kind: String,
    pub signatures: usize,
    pub schema: DefNode,
}

fn parse_def_type(s: &str) -> Option<DefType> {
    match s {
        "string" => Some(DefType::String),
        "integer" => Some(DefType::Integer),
        "boolean" => Some(DefType::Boolean),
        "object" => Some(DefType::Object),
        "array" => Some(DefType::Array),
        "ref" => Some(DefType::Ref),
        _ => None,
    }
}

fn parse_string_list(v: &Value) -> Option<Vec<String>> {
    let arr = v.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(item.as_str()?.to_string());
    }
    Some(out)
}

fn parse_def_node(v: &Value, is_object_property: bool) -> Option<DefNode> {
    let map = v.as_object()?;
    for k in map.keys() {
        if !ALLOWED_SCHEMA_KEYS.contains(&k.as_str()) {
            return None;
        }
    }

    let types = match map.get("type") {
        None => vec![DefType::Object],
        Some(Value::String(s)) => vec![parse_def_type(s)?],
        Some(Value::Array(arr)) => {
            if arr.is_empty() {
                return None;
            }
            let mut ts = Vec::with_capacity(arr.len());
            for item in arr {
                ts.push(parse_def_type(item.as_str()?)?);
            }
            ts
        }
        Some(_) => return None,
    };

    let enum_values = match map.get("enum") {
        None => None,
        Some(Value::Array(arr)) => Some(arr.clone()),
        Some(_) => return None,
    };

    let pattern = match map.get("pattern") {
        None => None,
        Some(Value::String(pat_str)) => {
            let compiled = CompiledBytePattern::compile(pat_str)?;
            let is_ts = pat_str == TIMESTAMP_PATTERN;
            Some((compiled, is_ts))
        }
        Some(_) => return None,
    };

    let minimum = match map.get("minimum") {
        None => None,
        Some(val) => Some(parse_v2_integer(val)?),
    };

    let maximum = match map.get("maximum") {
        None => None,
        Some(val) => Some(parse_v2_integer(val)?),
    };

    let items = match map.get("items") {
        None => None,
        Some(val) => Some(Box::new(parse_def_node(val, false)?)),
    };

    let mut properties = BTreeMap::new();
    if let Some(props_val) = map.get("properties") {
        let pmap = props_val.as_object()?;
        for (pk, pv) in pmap {
            properties.insert(pk.clone(), parse_def_node(pv, true)?);
        }
    }

    let additional_properties_false = match map.get("additionalProperties") {
        None => false,
        Some(Value::Bool(false)) => true,
        Some(Value::Bool(true)) => false,
        Some(_) => return None,
    };

    let values = match map.get("values") {
        None => None,
        Some(val) => Some(Box::new(parse_def_node(val, false)?)),
    };

    let required = match map.get("required") {
        None => Vec::new(),
        Some(val) => parse_string_list(val)?,
    };

    let non_empty = match map.get("nonEmpty") {
        None => Vec::new(),
        Some(val) => parse_string_list(val)?,
    };

    let mut ordered = Vec::new();
    if let Some(ord_val) = map.get("ordered") {
        let arr = ord_val.as_array()?;
        for pair_val in arr {
            let pair = parse_string_list(pair_val)?;
            if pair.len() != 2 {
                return None;
            }
            ordered.push((pair[0].clone(), pair[1].clone()));
        }
    }

    let mut exactly_one = Vec::new();
    if let Some(eo_val) = map.get("exactlyOne") {
        for group_val in eo_val.as_array()? {
            exactly_one.push(parse_string_list(group_val)?);
        }
    }

    let mut at_most_one = Vec::new();
    if let Some(amo_val) = map.get("atMostOne") {
        for group_val in amo_val.as_array()? {
            at_most_one.push(parse_string_list(group_val)?);
        }
    }

    let mut requires = Vec::new();
    if let Some(req_val) = map.get("requires") {
        for rule_val in req_val.as_array()? {
            let rmap = rule_val.as_object()?;
            if rmap.len() != 2 {
                return None;
            }
            let when_map = rmap.get("when")?.as_object()?;
            if when_map.len() != 2 {
                return None;
            }
            let when_field = when_map.get("field")?.as_str()?.to_string();
            let when_equals = when_map.get("equals")?.clone();
            let then_fields = parse_string_list(rmap.get("then")?)?;
            requires.push(RequiresRule {
                when_field,
                when_equals,
                then_fields,
            });
        }
    }

    let matches_signer = match map.get("matchesSigner") {
        None => None,
        Some(val) => {
            let pos = parse_v2_integer(val)?;
            if !(1..=16).contains(&pos) {
                return None;
            }
            Some(pos as usize)
        }
    };

    let key_bytes = match map.get("keyBytes") {
        None => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return None,
    };

    let derives = match map.get("derives") {
        None => None,
        Some(val) => {
            if !is_object_property {
                return None;
            }
            let dmap = val.as_object()?;
            if dmap.len() != 1 {
                return None;
            }
            let target = dmap.get("keyIdOf")?.as_str()?.to_string();
            Some(DerivesSpec::KeyIdOf(target))
        }
    };

    let ref_spec = match map.get("ref") {
        None => None,
        Some(val) => Some(RefSpec::parse(val)?),
    };

    let unique = match map.get("unique") {
        None => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return None,
    };

    let keys = match map.get("keys") {
        None => None,
        Some(Value::String(pat_str)) => Some(CompiledBytePattern::compile(pat_str)?),
        Some(_) => return None,
    };

    let max_entries = match map.get("maxEntries") {
        None => None,
        Some(val) => {
            let n = parse_v2_integer(val)?;
            if n < 1 {
                return None;
            }
            Some(n as usize)
        }
    };

    let max_length = match map.get("maxLength") {
        None => None,
        Some(val) => {
            let n = parse_v2_integer(val)?;
            if n < 1 {
                return None;
            }
            Some(n as usize)
        }
    };

    let node = DefNode {
        types,
        enum_values,
        pattern,
        minimum,
        maximum,
        items,
        properties,
        additional_properties_false,
        values,
        required,
        non_empty,
        ordered,
        exactly_one,
        at_most_one,
        requires,
        matches_signer,
        key_bytes,
        derives,
        ref_spec,
        unique,
        keys,
        max_entries,
        max_length,
    };

    // §2.8 / §2.9 document-level structural invariants.
    if node.ref_spec.is_some() && !node.types.contains(&DefType::Ref) {
        return None;
    }

    if node.unique && !node.is_exclusively_type(DefType::Array) {
        return None;
    }

    if node.keys.is_some() && !node.is_exclusively_type(DefType::Object) {
        return None;
    }

    if node.max_entries.is_some() && !node.is_exclusively_type(DefType::Object) {
        return None;
    }

    if node.max_length.is_some() && !node.types.contains(&DefType::String) {
        return None;
    }

    if node.matches_signer.is_some() && !node.is_exclusively_type(DefType::String) {
        return None;
    }

    if node.key_bytes {
        if !node.is_exclusively_type(DefType::Object) {
            return None;
        }
        let declares_props =
            node.properties.contains_key("algorithm") && node.properties.contains_key("bytes");
        let declares_req = node.required.iter().any(|r| r == "algorithm")
            && node.required.iter().any(|r| r == "bytes");
        if !declares_props || !declares_req {
            return None;
        }
    }

    if node.derives.is_some() && !node.is_exclusively_type(DefType::String) {
        return None;
    }

    // Verify every `derives` child property points to a sibling `keyBytes: true` property
    // that is also in this object node's `required`.
    for (prop_name, prop_node) in &node.properties {
        if let Some(DerivesSpec::KeyIdOf(ref target)) = prop_node.derives {
            if target == prop_name {
                return None;
            }
            let target_node = node.properties.get(target)?;
            if !target_node.key_bytes {
                return None;
            }
            if !node.required.iter().any(|r| r == target) {
                return None;
            }
        }
    }

    Some(node)
}

impl ParsedDefinition {
    /// Parses canonical JSON bytes into a validated §2.8 definition document.
    /// Returns `None` if not canonical JSON, wrong top-level shape, unknown schema member,
    /// malformed `keyBytes`/`derives`/`matchesSigner`, or signer rules do not fit `signatures`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let doc = parse_canonical_json(bytes)?;
        let top = doc.as_object()?;
        if top.get("format")?.as_str()? != "r5e.kind-definition/v1" {
            return None;
        }
        let kind = top.get("kind")?.as_str()?.to_string();
        let signatures = match top.get("signatures") {
            None => 1usize,
            Some(v) => {
                let s = parse_v2_integer(v)?;
                if !(1..=16).contains(&s) {
                    return None;
                }
                s as usize
            }
        };
        let schema_val = top.get("schema")?;
        if !schema_val.is_object() {
            return None;
        }
        let schema = parse_def_node(schema_val, false)?;

        // Signer-fit rules (§2.8):
        // 1. No `matchesSigner` anywhere in `schema` names a position above `signatures`.
        if schema.max_signer_referenced() > signatures {
            return None;
        }
        // 2. Every position from 2 to `signatures` is named by a `matchesSigner` on a property
        //    directly in `schema.properties` whose name is in `schema.required`.
        if signatures >= 2 {
            if !schema.is_exclusively_type(DefType::Object) {
                return None;
            }
            for pos in 2..=signatures {
                let bound_at_top = schema.properties.iter().any(|(prop_name, prop_node)| {
                    prop_node.matches_signer == Some(pos)
                        && schema.required.iter().any(|r| r == prop_name)
                });
                if !bound_at_top {
                    return None;
                }
            }
        }

        Some(Self {
            kind,
            signatures,
            schema,
        })
    }

    pub fn validate_body(&self, body: &Value, signers: &[String]) -> bool {
        validate_value(&self.schema, body, signers)
    }
}

fn parse_valid_key_bytes_obj(obj: &serde_json::Map<String, Value>) -> Option<(&str, Vec<u8>)> {
    let alg = obj.get("algorithm")?.as_str()?;
    if !is_registered_algorithm(alg) {
        return None;
    }
    let b64 = obj.get("bytes")?.as_str()?;
    let raw = decode_strict_base64(b64)?;
    if !is_key_admissible(alg, &raw) {
        return None;
    }
    Some((alg, raw))
}

fn matches_def_types(types: &[DefType], v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(_) => types.contains(&DefType::Boolean),
        Value::Number(_) => parse_v2_integer(v).is_some() && types.contains(&DefType::Integer),
        Value::String(_) => types.contains(&DefType::String) || types.contains(&DefType::Ref),
        Value::Array(_) => types.contains(&DefType::Array),
        Value::Object(_) => types.contains(&DefType::Object),
    }
}

fn json_values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(ba), Value::Bool(bb)) => ba == bb,
        (Value::String(sa), Value::String(sb)) => sa == sb,
        (Value::Number(_), Value::Number(_)) => {
            if let (Some(ia), Some(ib)) = (parse_v2_integer(a), parse_v2_integer(b)) {
                ia == ib
            } else {
                a == b
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            aa.len() == ab.len()
                && aa
                    .iter()
                    .zip(ab.iter())
                    .all(|(va, vb)| json_values_equal(va, vb))
        }
        (Value::Object(oa), Value::Object(ob)) => {
            oa.len() == ob.len()
                && oa
                    .iter()
                    .all(|(k, va)| ob.get(k).is_some_and(|vb| json_values_equal(va, vb)))
        }
        _ => false,
    }
}

fn array_items_unique(arr: &[Value]) -> bool {
    let mut encoded_seen = BTreeSet::new();
    let mut all_encoded = true;
    for item in arr {
        if let Some(enc) = encode_canonical_json(item) {
            if !encoded_seen.insert(enc) {
                return false;
            }
        } else {
            all_encoded = false;
            break;
        }
    }
    if all_encoded {
        return true;
    }
    for i in 0..arr.len() {
        for j in (i + 1)..arr.len() {
            if json_values_equal(&arr[i], &arr[j]) {
                return false;
            }
        }
    }
    true
}

fn validate_value(node: &DefNode, value: &Value, signers: &[String]) -> bool {
    if !matches_def_types(&node.types, value) {
        return false;
    }

    if let Some(enums) = &node.enum_values
        && !enums.iter().any(|e| json_values_equal(e, value))
    {
        return false;
    }

    match value {
        Value::String(s) => {
            if let Some(max_len) = node.max_length
                && s.len() > max_len
            {
                return false;
            }
            if let Some(ref_spec) = &node.ref_spec {
                if node.types.contains(&DefType::Ref) && !ref_spec.matches(s) {
                    return false;
                }
            } else if node.is_exclusively_type(DefType::Ref)
                && !(is_bytes_ref(s) || is_evidence_ref(s) || is_event_ref(s))
            {
                return false;
            }
            if let Some((compiled, is_ts)) = &node.pattern {
                if !compiled.is_match(s) {
                    return false;
                }
                if *is_ts && parse_rfc3339_instant(s, Some(9), false).is_none() {
                    return false;
                }
            }
            if let Some(pos) = node.matches_signer
                && signers.get(pos - 1).map(String::as_str) != Some(s.as_str())
            {
                return false;
            }
        }
        Value::Number(_) => {
            let Some(i) = parse_v2_integer(value) else {
                return false;
            };
            if let Some(min_i) = node.minimum
                && i < min_i
            {
                return false;
            }
            if let Some(max_i) = node.maximum
                && i > max_i
            {
                return false;
            }
        }
        Value::Array(arr) => {
            if let Some(items_node) = &node.items {
                for item in arr {
                    if !validate_value(items_node, item, signers) {
                        return false;
                    }
                }
            }
            if node.unique && !array_items_unique(arr) {
                return false;
            }
        }
        Value::Object(obj) => {
            if let Some(max_ent) = node.max_entries
                && obj.len() > max_ent
            {
                return false;
            }
            if let Some(keys_pat) = &node.keys {
                for k in obj.keys() {
                    if !keys_pat.is_match(k) {
                        return false;
                    }
                }
            }
            for req in &node.required {
                if !obj.contains_key(req) {
                    return false;
                }
            }
            if node.additional_properties_false {
                for k in obj.keys() {
                    if !node.properties.contains_key(k) {
                        return false;
                    }
                }
            }
            for (k, prop_node) in &node.properties {
                if let Some(v) = obj.get(k)
                    && !validate_value(prop_node, v, signers)
                {
                    return false;
                }
            }
            if let Some(values_node) = &node.values {
                for (k, v) in obj {
                    if !node.properties.contains_key(k) && !validate_value(values_node, v, signers)
                    {
                        return false;
                    }
                }
            }
            for ne_key in &node.non_empty {
                if let Some(v) = obj.get(ne_key) {
                    let is_empty = match v {
                        Value::String(s) => s.is_empty(),
                        Value::Array(a) => a.is_empty(),
                        Value::Object(m) => m.is_empty(),
                        _ => false,
                    };
                    if is_empty {
                        return false;
                    }
                }
            }
            for (first, second) in &node.ordered {
                if let (Some(v1), Some(v2)) = (obj.get(first), obj.get(second)) {
                    if let (Some(i1), Some(i2)) = (parse_v2_integer(v1), parse_v2_integer(v2)) {
                        if i1 > i2 {
                            return false;
                        }
                    } else if let (Some(s1), Some(s2)) = (v1.as_str(), v2.as_str()) {
                        let (Some(t1), Some(t2)) = (
                            parse_rfc3339_instant(s1, None, true),
                            parse_rfc3339_instant(s2, None, true),
                        ) else {
                            return false;
                        };
                        if t1 > t2 {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
            for group in &node.exactly_one {
                let count = group
                    .iter()
                    .filter(|name| obj.contains_key(name.as_str()))
                    .count();
                if count != 1 {
                    return false;
                }
            }
            for group in &node.at_most_one {
                let count = group
                    .iter()
                    .filter(|name| obj.contains_key(name.as_str()))
                    .count();
                if count > 1 {
                    return false;
                }
            }
            for rule in &node.requires {
                if obj.get(&rule.when_field) == Some(&rule.when_equals) {
                    for req_field in &rule.then_fields {
                        if !obj.contains_key(req_field) {
                            return false;
                        }
                    }
                }
            }
            if node.key_bytes && parse_valid_key_bytes_obj(obj).is_none() {
                return false;
            }
            for (prop_name, prop_node) in &node.properties {
                if let Some(DerivesSpec::KeyIdOf(ref key_field)) = prop_node.derives
                    && let Some(prop_val) = obj.get(prop_name)
                {
                    let Some(actual_kid) = prop_val.as_str() else {
                        return false;
                    };
                    let Some(key_obj) = obj.get(key_field).and_then(Value::as_object) else {
                        return false;
                    };
                    let Some((alg, raw_pk)) = parse_valid_key_bytes_obj(key_obj) else {
                        return false;
                    };
                    let Some(expected_kid) = compute_keyid(alg, &raw_pk) else {
                        return false;
                    };
                    if actual_kid != expected_kid {
                        return false;
                    }
                }
            }
        }
        Value::Bool(_) | Value::Null => {}
    }

    true
}
