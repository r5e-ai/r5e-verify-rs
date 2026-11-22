pub mod authority;
pub mod canonical;
pub mod crypto;
pub mod definition;
pub mod retention;
pub mod start;
pub mod wasm_ffi;
pub mod wire_schema;

use canonical::{
    MAX_SAFE_INT, bytes_ref_of, decode_base64, decode_hex_32, decode_strict_base64,
    encode_canonical_json, evidence_ref_of, hex_encode, is_evidence_ref, parse_canonical_json,
    parse_v2_integer, strict_json_parse,
};
use crypto::{
    DSSE_PAYLOAD_TYPE_V2, compute_keyid, dsse_pae, merkle_root, verify_inclusion_proof,
    verify_signature,
};
use definition::ParsedDefinition;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use start::PinnedChainOutcome;
pub use start::StartSummary;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use wire_schema::{WireSchemaKind, validate_wire_schema};

pub const REPORT_FORMAT_V2: &str = "r5e.provenance-verify-report/v2";
pub const R5E_API_CHAIN_REF: &str =
    "evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5";
pub const R5E_API_PUBLISHER_PIN: &str =
    "key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33=r5e.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub ok: usize,
    pub failed: usize,
    pub incomplete: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub layer: u8,
    pub subject: String,
    pub check: String,
    pub result: String,
    pub code: String,
    pub about: Option<String>,
}

impl Finding {
    pub fn new(
        layer: u8,
        subject: impl Into<String>,
        check: impl Into<String>,
        result: impl Into<String>,
        code: impl Into<String>,
        about: Option<String>,
    ) -> Self {
        Self {
            layer,
            subject: subject.into(),
            check: check.into(),
            result: result.into(),
            code: code.into(),
            about,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub start: Option<StartSummary>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self::from_findings_and_start(findings, None)
    }

    pub fn from_findings_and_start(
        mut findings: Vec<Finding>,
        start: Option<StartSummary>,
    ) -> Self {
        findings.sort_by(|a, b| {
            a.layer
                .cmp(&b.layer)
                .then_with(|| a.subject.as_bytes().cmp(b.subject.as_bytes()))
                .then_with(|| a.check.as_bytes().cmp(b.check.as_bytes()))
                .then_with(|| a.code.as_bytes().cmp(b.code.as_bytes()))
                .then_with(|| {
                    a.about
                        .as_deref()
                        .unwrap_or("")
                        .as_bytes()
                        .cmp(b.about.as_deref().unwrap_or("").as_bytes())
                })
                .then_with(|| a.result.as_bytes().cmp(b.result.as_bytes()))
        });

        let mut ok = 0usize;
        let mut failed = 0usize;
        let mut incomplete = 0usize;
        for f in &findings {
            match f.result.as_str() {
                "ok" => ok += 1,
                "failed" => failed += 1,
                "incomplete" => incomplete += 1,
                _ => {}
            }
        }

        Self {
            format: REPORT_FORMAT_V2.to_string(),
            start,
            summary: Summary {
                ok,
                failed,
                incomplete,
            },
            findings,
        }
    }

    pub fn is_sound(&self) -> bool {
        self.summary.failed == 0
    }

    pub fn is_established(&self) -> bool {
        self.summary.failed == 0 && self.summary.incomplete == 0
    }

    /// §10 CLI exit status (`0` established, `1` failed, `3` incomplete unless `allow_incomplete`).
    pub fn exit_code(&self, allow_incomplete: bool) -> i32 {
        if self.summary.failed > 0 {
            1
        } else if self.summary.incomplete > 0 && !allow_incomplete {
            3
        } else {
            0
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("Report serializes to JSON Value")
    }

    /// §9 Canonical JSON (§2.1) encoding of the report.
    pub fn to_canonical_json(&self) -> String {
        encode_canonical_json(&self.to_value())
            .expect("Report always fits restricted canonical JSON")
    }
}

/// Base definition documents loaded as raw bytes and matched by `bytes:sha256:` hash.
#[derive(Debug, Clone)]
pub struct BaseDefinitions {
    index_refs: BTreeSet<String>,
    by_ref: BTreeMap<String, Vec<u8>>,
}

impl BaseDefinitions {
    pub fn from_index_and_files(
        index_json: &[u8],
        files_by_kind_path: &[(&str, &[u8])],
    ) -> Result<Self, InputError> {
        let idx_val = strict_json_parse(index_json)
            .ok_or_else(|| InputError("definitions/index.json is not valid JSON".into()))?;
        let idx_map = idx_val
            .as_object()
            .ok_or_else(|| InputError("definitions/index.json must be an object".into()))?;

        let mut index_refs = BTreeSet::new();
        for (kind_path, ref_val) in idx_map {
            let r = ref_val.as_str().ok_or_else(|| {
                InputError(format!("index entry for {kind_path} must be a string"))
            })?;
            index_refs.insert(r.to_string());
        }

        let mut by_ref = BTreeMap::new();
        for &(kind_path, raw_bytes) in files_by_kind_path {
            let computed = bytes_ref_of(raw_bytes);
            if let Some(expected) = idx_map.get(kind_path).and_then(Value::as_str)
                && expected != computed
            {
                return Err(InputError(format!(
                    "base definition {kind_path} hashed to {computed}, expected {expected}"
                )));
            }
            by_ref.insert(computed, raw_bytes.to_vec());
        }

        Ok(Self { index_refs, by_ref })
    }

    pub fn get_bytes(&self, schema_ref: &str) -> Option<&[u8]> {
        let bytes = self.by_ref.get(schema_ref)?;
        if bytes_ref_of(bytes) == schema_ref {
            Some(bytes.as_slice())
        } else {
            None
        }
    }

    pub fn contains_index_ref(&self, r: &str) -> bool {
        self.index_refs.contains(r)
    }
}

static DEFAULT_BASE_DEFINITIONS: LazyLock<BaseDefinitions> = LazyLock::new(|| {
    let index_bytes = include_bytes!("../../vendor/provenance-v2/definitions/index.json");
    let files: &[(&str, &[u8])] = &[
        (
            "core.r5e.io/v1/Artifact",
            include_bytes!("../../vendor/provenance-v2/definitions/core.r5e.io/v1/Artifact.json"),
        ),
        (
            "core.r5e.io/v1/KindDefinition",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/core.r5e.io/v1/KindDefinition.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Badge",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Badge.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/ChainStarted",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/ChainStarted.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Checkpoint",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Checkpoint.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/DefinitionPublished",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/DefinitionPublished.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Deployment",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Deployment.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Disclosure",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Disclosure.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Endorsement",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Endorsement.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/EpochSeal",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/EpochSeal.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/ModelCall",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/ModelCall.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/ModelResponse",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/ModelResponse.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Observation",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Observation.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/PayloadDisposition",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/PayloadDisposition.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/PolicyDecision",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/PolicyDecision.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Principal",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Principal.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/PublishedView",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/PublishedView.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/RetentionHold",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/RetentionHold.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/RetentionHoldRelease",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/RetentionHoldRelease.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Revocation",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Revocation.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/RootChangeApproval",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/RootChangeApproval.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/RootsChanged",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/RootsChanged.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/SessionClosed",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/SessionClosed.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/SessionOpened",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/SessionOpened.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Succession",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Succession.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/ToolCall",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/ToolCall.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/ToolResult",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/ToolResult.json"
            ),
        ),
        (
            "provenance.r5e.io/v2/Verification",
            include_bytes!(
                "../../vendor/provenance-v2/definitions/provenance.r5e.io/v2/Verification.json"
            ),
        ),
    ];
    BaseDefinitions::from_index_and_files(index_bytes, files)
        .expect("embedded base definitions must match index.json")
});

pub fn default_base_definitions() -> &'static BaseDefinitions {
    &DEFAULT_BASE_DEFINITIONS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherScope {
    AllDomains,
    Domains(BTreeSet<String>),
}

#[derive(Debug, Clone, Default)]
pub struct PublisherTrust {
    by_key: BTreeMap<String, PublisherScope>,
}

pub fn domain_covers_group(domain: &str, group: &str) -> bool {
    if group == domain {
        return true;
    }
    group
        .strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

pub fn parse_publisher_entry(spec: &str) -> Result<(&str, Option<Vec<&str>>), InputError> {
    if spec.is_empty() {
        return Err(InputError("trusted publisher must not be empty".into()));
    }
    if let Some((key_id, domains_raw)) = spec.split_once('=') {
        if key_id.is_empty() {
            return Err(InputError(
                "trusted publisher must name a key id before '='".into(),
            ));
        }
        let domains: Vec<&str> = domains_raw.split(',').collect();
        if domains.is_empty()
            || domains
                .iter()
                .any(|d| d.is_empty() || d.contains(['=', '/', ' ', '\t', '\n', '\r']))
        {
            return Err(InputError(format!(
                "invalid domain list in trusted publisher '{spec}'"
            )));
        }
        Ok((key_id, Some(domains)))
    } else {
        Ok((spec, None))
    }
}

impl PublisherTrust {
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = &'a String>) -> Self {
        let mut out = Self::default();
        for spec in entries {
            if let Ok((key_id, domains_opt)) = parse_publisher_entry(spec) {
                match domains_opt {
                    None => {
                        out.by_key
                            .insert(key_id.to_string(), PublisherScope::AllDomains);
                    }
                    Some(doms) => match out.by_key.get_mut(key_id) {
                        Some(PublisherScope::AllDomains) => {}
                        Some(PublisherScope::Domains(set)) => {
                            for d in doms {
                                set.insert(d.to_string());
                            }
                        }
                        None => {
                            let mut set = BTreeSet::new();
                            for d in doms {
                                set.insert(d.to_string());
                            }
                            out.by_key
                                .insert(key_id.to_string(), PublisherScope::Domains(set));
                        }
                    },
                }
            }
        }
        out
    }

    pub fn contains_publisher(&self, key_id: &str) -> bool {
        self.by_key.contains_key(key_id)
    }

    pub fn believes(&self, key_id: &str, kind_path: &str) -> bool {
        let Some(scope) = self.by_key.get(key_id) else {
            return false;
        };
        match scope {
            PublisherScope::AllDomains => true,
            PublisherScope::Domains(domains) => {
                let Some((group, _)) = kind_path.split_once('/') else {
                    return false;
                };
                if group.is_empty() {
                    return false;
                }
                domains.iter().any(|d| domain_covers_group(d, group))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub trusted_profiles: BTreeSet<String>,
    pub trusted_publishers: BTreeSet<String>,
    pub trusted_roots: Option<BTreeSet<String>>,
    pub trusted_chain: Option<String>,
    pub min_start_seq: Option<u64>,
    pub installed_definitions: BTreeMap<String, Vec<u8>>,
    pub base_definitions: Option<BaseDefinitions>,
}

impl VerifyOptions {
    pub fn insert_installed_definition_bytes(&mut self, bytes: Vec<u8>) -> String {
        let r = bytes_ref_of(&bytes);
        self.installed_definitions.insert(r.clone(), bytes);
        r
    }

    pub fn add_trusted_publisher(&mut self, spec: impl Into<String>) -> Result<(), InputError> {
        let s = spec.into();
        parse_publisher_entry(&s)?;
        self.trusted_publishers.insert(s);
        Ok(())
    }

    /// Validates reader input invariants (`VERIFY-V2.md` §10 / `A6` §2.1 / `A9` §4).
    pub fn validate(&self) -> Result<(), InputError> {
        for pub_spec in &self.trusted_publishers {
            parse_publisher_entry(pub_spec)?;
        }
        if self.trusted_roots.is_some() && self.trusted_chain.is_some() {
            return Err(InputError(
                "trustedRoots and trustedChain are mutually exclusive".into(),
            ));
        }
        if let Some(tc) = &self.trusted_chain
            && !is_evidence_ref(tc)
        {
            return Err(InputError(
                "trustedChain must be an evidence:sha256:<64 lowercase hex> reference".into(),
            ));
        }
        if let Some(ms) = self.min_start_seq
            && !(2..=MAX_SAFE_INT as u64).contains(&ms)
        {
            return Err(InputError("minStartSeq must be an integer >= 2".into()));
        }
        Ok(())
    }
}

/// Parses raw bundle JSON bytes strictly (rejecting invalid UTF-8, syntax errors,
/// duplicate keys, and `-0`), validates reader options, and verifies the bundle
/// offline with zero OS/clock calls.
pub fn verify_bundle_bytes(
    bundle_bytes: &[u8],
    opts: &VerifyOptions,
) -> Result<Report, InputError> {
    opts.validate()?;
    let bundle_val = strict_json_parse(bundle_bytes)
        .ok_or_else(|| InputError("bundle is not readable JSON".into()))?;
    Ok(verify_bundle_value(&bundle_val, opts))
}

struct AvailableKey {
    algorithm: String,
    bytes: Vec<u8>,
}

pub(crate) struct OpenedRecord {
    pub(crate) rec_ref: String,
    pub(crate) payload: Value,
    pub(crate) signers: Vec<String>,
    pub(crate) all_sigs_ok: bool,
}

impl OpenedRecord {
    pub(crate) fn kind_path(&self) -> Option<String> {
        let api_version = self.payload.get("apiVersion")?.as_str()?;
        let kind = self.payload.get("kind")?.as_str()?;
        Some(format!("{api_version}/{kind}"))
    }
}

struct PublishedStatement {
    pub_ref: String,
    issuer: String,
    kind_path: String,
    definition_ref: String,
}

fn has_matching_issuer_binding(
    bindings_val: &Value,
    rec_stream: Option<&str>,
    rec_actor: Option<&str>,
    rec_issuer: &str,
) -> bool {
    let (Some(stream), Some(actor), Some(bindings)) =
        (rec_stream, rec_actor, bindings_val.as_array())
    else {
        return false;
    };
    bindings.iter().any(|binding| {
        let stream_ok = binding
            .get("streamPrefix")
            .and_then(Value::as_str)
            .is_some_and(|sp| stream.starts_with(sp));
        let actor_ok = binding
            .get("actorPrefixes")
            .and_then(Value::as_array)
            .is_some_and(|aps| {
                aps.iter()
                    .any(|ap| ap.as_str().is_some_and(|p| actor.starts_with(p)))
            });
        let issuer_ok = binding
            .get("issuerKeys")
            .and_then(Value::as_array)
            .is_some_and(|iks| iks.iter().any(|ik| ik.as_str() == Some(rec_issuer)));
        stream_ok && actor_ok && issuer_ok
    })
}

fn has_matching_sealer_binding(
    profile_val: &Value,
    sealed_stream: Option<&str>,
    seal_issuer: &str,
) -> bool {
    let Some(stream) = sealed_stream else {
        return false;
    };
    let Some(bindings) = profile_val
        .get("authority")
        .and_then(|a| a.get("bindings"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    bindings.iter().any(|binding| {
        let stream_ok = binding
            .get("streamPrefix")
            .and_then(Value::as_str)
            .is_some_and(|sp| stream.starts_with(sp));
        let sealer_ok = binding
            .get("sealerKeys")
            .and_then(Value::as_array)
            .is_some_and(|sks| sks.iter().any(|sk| sk.as_str() == Some(seal_issuer)));
        stream_ok && sealer_ok
    })
}

/// Core pure verification entry point (`VERIFY-V2.md` §§3–9).
pub fn verify_bundle_value(bundle: &Value, opts: &VerifyOptions) -> Report {
    let base_defs = opts
        .base_definitions
        .as_ref()
        .unwrap_or_else(|| default_base_definitions());

    // §3. The bundle
    if !validate_wire_schema(WireSchemaKind::Export, bundle) {
        return Report::from_findings(vec![Finding::new(
            1,
            "bundle",
            "shape",
            "failed",
            "malformed_bundle",
            None,
        )]);
    }

    let records_arr = bundle["records"].as_array().expect("export schema checked");
    {
        let mut seen_record_refs = BTreeSet::new();
        for entry in records_arr {
            let r = entry["ref"].as_str().expect("export schema checked");
            if !seen_record_refs.insert(r) {
                return Report::from_findings(vec![Finding::new(
                    1,
                    "bundle",
                    "shape",
                    "failed",
                    "malformed_bundle",
                    None,
                )]);
            }
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    // §4. Blobs and keys
    let mut valid_blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for blob in bundle["blobs"].as_array().expect("export schema checked") {
        let blob_ref = blob["ref"].as_str().expect("export schema checked");
        let b64 = blob["base64"].as_str().expect("export schema checked");
        match decode_base64(b64) {
            None => {
                findings.push(Finding::new(
                    2,
                    blob_ref,
                    "content_hash",
                    "failed",
                    "invalid_base64",
                    None,
                ));
            }
            Some(raw) => {
                if bytes_ref_of(&raw) != blob_ref {
                    findings.push(Finding::new(
                        2,
                        blob_ref,
                        "content_hash",
                        "failed",
                        "bytes_do_not_match_reference",
                        None,
                    ));
                } else {
                    valid_blobs.insert(blob_ref.to_string(), raw);
                }
            }
        }
    }

    let mut available_keys: BTreeMap<String, AvailableKey> = BTreeMap::new();
    for key_entry in bundle["keys"].as_array().expect("export schema checked") {
        let keyid = key_entry["keyid"].as_str().expect("export schema checked");
        let alg = key_entry["algorithm"]
            .as_str()
            .expect("export schema checked");
        let b64 = key_entry["bytes"].as_str().expect("export schema checked");
        let Some(raw) = decode_base64(b64) else {
            findings.push(Finding::new(
                1,
                keyid,
                "key",
                "failed",
                "conflicting_or_unreadable_key",
                None,
            ));
            continue;
        };
        if let Some(existing) = available_keys.get(keyid) {
            if existing.bytes != raw {
                findings.push(Finding::new(
                    1,
                    keyid,
                    "key",
                    "failed",
                    "conflicting_or_unreadable_key",
                    None,
                ));
            }
        } else {
            available_keys.insert(
                keyid.to_string(),
                AvailableKey {
                    algorithm: alg.to_string(),
                    bytes: raw,
                },
            );
        }
    }

    // §5. Layer 1: identity and signatures
    let mut opened_records: Vec<OpenedRecord> = Vec::new();
    let mut opened_by_ref: BTreeMap<String, usize> = BTreeMap::new();
    let mut any_sig_failed_by_idx: Vec<bool> = Vec::new();

    'records: for rec_entry in records_arr {
        let rec_ref = rec_entry["ref"].as_str().expect("export schema checked");
        let env = &rec_entry["envelope"];

        if !validate_wire_schema(WireSchemaKind::SignedEvidence, env) {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "malformed_envelope",
                None,
            ));
            continue;
        }

        let payload_b64 = env["payload"].as_str().expect("signed-evidence schema");
        let Some(payload_bytes) = decode_strict_base64(payload_b64) else {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "invalid_base64",
                None,
            ));
            continue;
        };

        let sig_entries = env["signatures"]
            .as_array()
            .expect("signed-evidence schema");
        let mut signers: Vec<String> = Vec::with_capacity(sig_entries.len());
        let mut sig_bytes_list: Vec<Vec<u8>> = Vec::with_capacity(sig_entries.len());
        for sig_entry in sig_entries {
            let sig_b64 = sig_entry["sig"].as_str().expect("signed-evidence schema");
            let Some(sb) = decode_strict_base64(sig_b64) else {
                findings.push(Finding::new(
                    1,
                    rec_ref,
                    "identity",
                    "failed",
                    "invalid_base64",
                    None,
                ));
                continue 'records;
            };
            let kid = sig_entry["keyid"].as_str().expect("signed-evidence schema");
            signers.push(kid.to_string());
            sig_bytes_list.push(sb);
        }

        let Some(payload_val) = parse_canonical_json(&payload_bytes) else {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "payload_not_canonical",
                None,
            ));
            continue;
        };

        let Some(payload_obj) = payload_val.as_object() else {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "payload_not_an_object",
                None,
            ));
            continue;
        };

        if payload_obj.get("issuer").and_then(Value::as_str) != Some(signers[0].as_str()) {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "issuer_is_not_signer",
                None,
            ));
            continue;
        }

        {
            let mut uniq_signers = BTreeSet::new();
            if signers.iter().any(|kid| !uniq_signers.insert(kid.as_str())) {
                findings.push(Finding::new(
                    1,
                    rec_ref,
                    "identity",
                    "failed",
                    "duplicate_signer",
                    None,
                ));
                continue;
            }
        }

        let computed_ref = evidence_ref_of(&payload_bytes);
        if computed_ref != rec_ref {
            findings.push(Finding::new(
                1,
                rec_ref,
                "identity",
                "failed",
                "payload_hashes_to_another_reference",
                Some(computed_ref),
            ));
            continue;
        }

        findings.push(Finding::new(1, rec_ref, "identity", "ok", "ok", None));

        let pae_msg = dsse_pae(DSSE_PAYLOAD_TYPE_V2, &payload_bytes);
        let mut all_sigs_ok = true;
        let mut any_sig_failed = false;
        for (sig_kid, sig_bytes) in signers.iter().zip(sig_bytes_list.iter()) {
            match available_keys.get(sig_kid) {
                None => {
                    all_sigs_ok = false;
                    findings.push(Finding::new(
                        1,
                        rec_ref,
                        "signature",
                        "incomplete",
                        "missing_key",
                        Some(sig_kid.clone()),
                    ));
                }
                Some(akey) => {
                    if compute_keyid(&akey.algorithm, &akey.bytes).as_deref()
                        != Some(sig_kid.as_str())
                    {
                        all_sigs_ok = false;
                        any_sig_failed = true;
                        findings.push(Finding::new(
                            1,
                            rec_ref,
                            "signature",
                            "failed",
                            "key_mismatch",
                            Some(sig_kid.clone()),
                        ));
                    } else if !verify_signature(&akey.algorithm, &akey.bytes, sig_bytes, &pae_msg) {
                        all_sigs_ok = false;
                        any_sig_failed = true;
                        findings.push(Finding::new(
                            1,
                            rec_ref,
                            "signature",
                            "failed",
                            "bad_signature",
                            Some(sig_kid.clone()),
                        ));
                    } else {
                        findings.push(Finding::new(
                            1,
                            rec_ref,
                            "signature",
                            "ok",
                            "ok",
                            Some(sig_kid.clone()),
                        ));
                    }
                }
            }
        }

        let idx = opened_records.len();
        opened_by_ref.insert(rec_ref.to_string(), idx);
        any_sig_failed_by_idx.push(any_sig_failed);
        opened_records.push(OpenedRecord {
            rec_ref: rec_ref.to_string(),
            payload: payload_val,
            signers,
            all_sigs_ok,
        });
    }

    // §6.2a Collect verified `DefinitionPublished` statements across opened records.
    let mut published_statements: Vec<PublishedStatement> = Vec::new();
    for rec in &opened_records {
        if rec.all_sigs_ok
            && rec.kind_path().as_deref() == Some("provenance.r5e.io/v2/DefinitionPublished")
            && let Some(defs) = rec
                .payload
                .get("body")
                .and_then(|b| b.get("definitions"))
                .and_then(Value::as_array)
        {
            for entry in defs {
                if let (Some(k), Some(d)) = (
                    entry.get("kind").and_then(Value::as_str),
                    entry.get("definition").and_then(Value::as_str),
                ) {
                    published_statements.push(PublishedStatement {
                        pub_ref: rec.rec_ref.clone(),
                        issuer: rec.signers[0].clone(),
                        kind_path: k.to_string(),
                        definition_ref: d.to_string(),
                    });
                }
            }
        }
    }
    published_statements.sort_by(|a, b| a.pub_ref.as_bytes().cmp(b.pub_ref.as_bytes()));

    // Pre-index omissions by `ref` (preserving first reason if repeated).
    let mut omissions_by_ref: BTreeMap<String, String> = BTreeMap::new();
    for om in bundle["omissions"].as_array().expect("export schema") {
        let om_ref = om["ref"].as_str().expect("export schema");
        let om_reason = om["reason"].as_str().expect("export schema");
        omissions_by_ref
            .entry(om_ref.to_string())
            .or_insert_with(|| om_reason.to_string());
    }

    // §6. Layer 2: per-record checks
    // Pass 1: evaluate `body` across all opened records first so `ChainStarted`'s
    // `publication` check (`A6` §3 Row 2) can inspect `P`'s `body` finding regardless
    // of record ordering in `bundle.records`.
    let emit_profile_authority = opts.trusted_roots.is_none() && opts.trusted_chain.is_none();
    let mut body_result_by_idx: Vec<String> = Vec::with_capacity(opened_records.len());
    let mut multi_sig_mismatch_by_idx: Vec<bool> = Vec::with_capacity(opened_records.len());
    for rec in &opened_records {
        // §6.1 & §6.2: `body` finding
        let body_finding = check_record_body(rec, base_defs, opts, &valid_blobs);
        body_result_by_idx.push(body_finding.result.clone());
        findings.push(body_finding);
        multi_sig_mismatch_by_idx.push(has_multi_signer_count_mismatch(
            rec,
            base_defs,
            opts,
            &valid_blobs,
        ));
    }

    let publisher_trust = PublisherTrust::from_entries(&opts.trusted_publishers);
    let mut profile_bounds_ok_by_idx = vec![false; opened_records.len()];
    let mut authority_ok_by_idx = vec![false; opened_records.len()];

    for (rec_idx, rec) in opened_records.iter().enumerate() {
        // §6.2a & A6 §3 & A9 §4: `publication` finding
        if let Some(cs_pub) = start::check_chain_started_publication(
            rec_idx,
            &opened_records,
            &opened_by_ref,
            &any_sig_failed_by_idx,
            &body_result_by_idx,
            &publisher_trust,
        ) {
            findings.push(cs_pub);
        } else {
            findings.push(check_record_publication(
                rec,
                &published_statements,
                &publisher_trust,
            ));
        }

        // §6.3 / A6 §2.2: `profile_bounds` (and §6.3 `authority` when neither `trusted_roots`
        // nor `trusted_chain` is supplied)
        let (bounds_ok, prof_auth_ok) = check_record_profile(
            rec,
            &valid_blobs,
            &opts.trusted_profiles,
            emit_profile_authority,
            &mut findings,
        );
        profile_bounds_ok_by_idx[rec_idx] = bounds_ok;
        if prof_auth_ok {
            authority_ok_by_idx[rec_idx] = true;
        }
    }

    // §6.5: Links within a stream
    let mut streams: BTreeMap<String, BTreeMap<i64, Vec<&OpenedRecord>>> = BTreeMap::new();
    for rec in &opened_records {
        if let (Some(stream), Some(seq)) = (
            rec.payload.get("stream").and_then(Value::as_str),
            rec.payload.get("seq").and_then(parse_v2_integer),
        ) && seq >= 1
        {
            streams
                .entry(stream.to_string())
                .or_default()
                .entry(seq)
                .or_default()
                .push(rec);
        }
    }
    for (stream, by_seq) in &streams {
        for (&seq, recs_at_pos) in by_seq {
            if recs_at_pos.len() >= 2 {
                findings.push(Finding::new(
                    2,
                    stream,
                    "fork",
                    "failed",
                    "two_records_at_one_position",
                    Some(format!("seq:{seq}")),
                ));
            } else if recs_at_pos.len() == 1
                && seq > 1
                && let Some(prev_recs) = by_seq.get(&(seq - 1))
                && prev_recs.len() == 1
            {
                let cur_rec = recs_at_pos[0];
                let prior_rec = prev_recs[0];
                if cur_rec.payload.get("previous").and_then(Value::as_str)
                    == Some(prior_rec.rec_ref.as_str())
                {
                    findings.push(Finding::new(
                        2,
                        &cur_rec.rec_ref,
                        "previous",
                        "ok",
                        "ok",
                        Some(prior_rec.rec_ref.clone()),
                    ));
                } else {
                    findings.push(Finding::new(
                        2,
                        &cur_rec.rec_ref,
                        "previous",
                        "failed",
                        "previous_is_not_the_prior_record",
                        Some(prior_rec.rec_ref.clone()),
                    ));
                }
            }
        }
    }

    // §7. Layer 3: seals
    let mut seal_refs: Vec<String> = Vec::new();
    let mut seen_seals: BTreeSet<String> = BTreeSet::new();
    for s in bundle["seals"].as_array().expect("export schema") {
        let sref = s.as_str().expect("export schema");
        if seen_seals.insert(sref.to_string()) {
            seal_refs.push(sref.to_string());
        }
    }
    let proofs_arr = bundle["proofs"].as_array().expect("export schema");
    for p in proofs_arr {
        let sref = p["seal"].as_str().expect("export schema");
        if seen_seals.insert(sref.to_string()) {
            seal_refs.push(sref.to_string());
        }
    }

    struct CheckedSealChainEntry {
        seal_ref: String,
        stream: Option<String>,
        range: Option<(i64, i64)>,
        pred_finding: Option<Finding>,
        covered_events: Option<Vec<String>>,
    }

    let mut seal_covered_records: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sealer_ok_seal_refs: BTreeSet<String> = BTreeSet::new();
    let mut disqualified_coverage_seals: BTreeSet<String> = BTreeSet::new();
    let mut checked_epoch_seals: Vec<CheckedSealChainEntry> = Vec::new();

    for seal_ref in &seal_refs {
        let Some(&seal_idx) = opened_by_ref.get(seal_ref) else {
            disqualified_coverage_seals.insert(seal_ref.to_string());
            findings.push(Finding::new(
                3,
                seal_ref,
                "seal",
                "incomplete",
                "seal_record_not_carried",
                None,
            ));
            continue;
        };
        let seal_rec = &opened_records[seal_idx];
        if seal_rec.kind_path().as_deref() != Some("provenance.r5e.io/v2/EpochSeal") {
            disqualified_coverage_seals.insert(seal_ref.to_string());
            findings.push(Finding::new(
                3,
                seal_ref,
                "seal",
                "failed",
                "not_an_epoch_seal",
                None,
            ));
            continue;
        }

        // Sealer finding
        let seal_pref_opt = seal_rec.payload.get("profileRef").and_then(Value::as_str);
        let seal_prof_opt = seal_pref_opt
            .and_then(|pr| valid_blobs.get(pr))
            .and_then(|b| parse_canonical_json(b));
        match seal_prof_opt {
            None => {
                findings.push(Finding::new(
                    3,
                    seal_ref,
                    "sealer",
                    "incomplete",
                    "profile_not_available",
                    seal_pref_opt.map(str::to_string),
                ));
            }
            Some(prof_val) => {
                let sealed_stream = seal_rec
                    .payload
                    .get("body")
                    .and_then(|b| b.get("stream"))
                    .and_then(Value::as_str);
                let seal_issuer = seal_rec.signers[0].as_str();
                if has_matching_sealer_binding(&prof_val, sealed_stream, seal_issuer) {
                    sealer_ok_seal_refs.insert(seal_ref.to_string());
                    findings.push(Finding::new(
                        3,
                        seal_ref,
                        "sealer",
                        "ok",
                        "ok",
                        Some(seal_issuer.to_string()),
                    ));
                } else {
                    findings.push(Finding::new(
                        3,
                        seal_ref,
                        "sealer",
                        "failed",
                        "unauthorized_seal",
                        Some(seal_issuer.to_string()),
                    ));
                }
            }
        }

        // Epoch finding (§7) and predecessor seal_chain check (§7a / A9 §3)
        let (epoch_finding, covered_events_opt) =
            check_seal_epoch(seal_rec, &valid_blobs, &opened_records, &opened_by_ref);
        if epoch_finding.result == "failed" {
            disqualified_coverage_seals.insert(seal_ref.to_string());
        }
        findings.push(epoch_finding);

        let seal_body = seal_rec.payload.get("body").unwrap_or(&json!(null));
        let stream = seal_body
            .get("stream")
            .and_then(Value::as_str)
            .map(str::to_string);
        let range = match (
            seal_body.get("firstSeq").and_then(parse_v2_integer),
            seal_body.get("lastSeq").and_then(parse_v2_integer),
        ) {
            (Some(fs), Some(ls)) if fs >= 1 && fs <= ls => Some((fs, ls)),
            _ => None,
        };
        let pred_finding = check_seal_chain(seal_rec, &opened_records, &opened_by_ref);
        checked_epoch_seals.push(CheckedSealChainEntry {
            seal_ref: seal_ref.to_string(),
            stream,
            range,
            pred_finding,
            covered_events: covered_events_opt,
        });
    }

    // Finalize `seal_chain` findings (applying §7a overlap check) and populate `seal_covered_records`.
    for (idx, entry) in checked_epoch_seals.iter().enumerate() {
        let pred_failed = entry
            .pred_finding
            .as_ref()
            .is_some_and(|f| f.result == "failed");

        let final_sc_finding = if pred_failed {
            entry.pred_finding.clone()
        } else if let (Some(stream_a), Some((first_a, last_a))) = (&entry.stream, entry.range) {
            let min_overlap_ref = checked_epoch_seals
                .iter()
                .enumerate()
                .filter(|(j, other)| {
                    *j != idx
                        && other.stream.as_ref() == Some(stream_a)
                        && other
                            .range
                            .is_some_and(|(first_b, last_b)| first_a <= last_b && first_b <= last_a)
                })
                .map(|(_, other)| other.seal_ref.as_str())
                .min_by(|x, y| x.as_bytes().cmp(y.as_bytes()));

            if let Some(other_ref) = min_overlap_ref {
                Some(Finding::new(
                    3,
                    &entry.seal_ref,
                    "seal_chain",
                    "failed",
                    "seal_ranges_overlap",
                    Some(other_ref.to_string()),
                ))
            } else {
                entry.pred_finding.clone()
            }
        } else {
            entry.pred_finding.clone()
        };

        if final_sc_finding
            .as_ref()
            .is_some_and(|f| f.result == "failed")
        {
            disqualified_coverage_seals.insert(entry.seal_ref.clone());
        }
        if let Some(sc_f) = final_sc_finding {
            findings.push(sc_f);
        }
        if let Some(ref covered_events) = entry.covered_events
            && !disqualified_coverage_seals.contains(&entry.seal_ref)
        {
            seal_covered_records
                .entry(entry.seal_ref.clone())
                .or_default()
                .extend(covered_events.iter().cloned());
        }
    }

    // §8. Layer 3: membership proofs
    for proof in proofs_arr {
        let rec_ref = proof["record"].as_str().expect("export schema");
        let seal_ref = proof["seal"].as_str().expect("export schema");
        let index = parse_v2_integer(&proof["index"]).expect("export schema");
        let siblings_arr = proof["siblings"].as_array().expect("export schema");

        let (Some(&seal_idx), Some(&rec_idx)) =
            (opened_by_ref.get(seal_ref), opened_by_ref.get(rec_ref))
        else {
            findings.push(Finding::new(
                3,
                rec_ref,
                "membership",
                "incomplete",
                "seal_or_record_not_carried",
                Some(seal_ref.to_string()),
            ));
            continue;
        };

        let seal_rec = &opened_records[seal_idx];
        let cov_rec = &opened_records[rec_idx];
        let seal_body = seal_rec.payload.get("body").unwrap_or(&json!(null));
        let sealed_stream = seal_body.get("stream").and_then(Value::as_str);
        let first_seq = seal_body.get("firstSeq").and_then(parse_v2_integer);
        let rec_stream = cov_rec.payload.get("stream").and_then(Value::as_str);
        let rec_seq = cov_rec.payload.get("seq").and_then(parse_v2_integer);

        let pos_matches = match (rec_stream, sealed_stream, rec_seq, first_seq) {
            (Some(rs), Some(ss), Some(rseq), Some(fseq)) => {
                rs == ss && (rseq as i128) == (fseq as i128) + (index as i128)
            }
            _ => false,
        };
        if !pos_matches {
            findings.push(Finding::new(
                3,
                rec_ref,
                "membership",
                "failed",
                "position_does_not_match_seal",
                Some(seal_ref.to_string()),
            ));
            continue;
        }

        let first_seq_i = first_seq.unwrap();
        let last_seq_opt = seal_body.get("lastSeq").and_then(parse_v2_integer);
        let root_digest_opt = seal_body
            .get("root")
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("sha256:"))
            .and_then(decode_hex_32);
        let leaf_digest_opt = rec_ref
            .strip_prefix("evidence:sha256:")
            .and_then(decode_hex_32);
        let siblings_opt: Option<Vec<[u8; 32]>> = siblings_arr
            .iter()
            .map(|sv| {
                sv.as_str()
                    .and_then(|s| s.strip_prefix("sha256:"))
                    .and_then(decode_hex_32)
            })
            .collect();

        let proof_ok = match (last_seq_opt, root_digest_opt, leaf_digest_opt, siblings_opt) {
            (Some(last_seq_i), Some(expected_root), Some(leaf_digest), Some(siblings)) => {
                let tree_size_i128 = (last_seq_i as i128) - (first_seq_i as i128) + 1;
                if index >= 0
                    && tree_size_i128 >= 1
                    && let Ok(tree_size) = u64::try_from(tree_size_i128)
                {
                    verify_inclusion_proof(
                        &leaf_digest,
                        index as u64,
                        tree_size,
                        &siblings,
                        &expected_root,
                    )
                } else {
                    false
                }
            }
            _ => false,
        };

        if !proof_ok {
            findings.push(Finding::new(
                3,
                rec_ref,
                "membership",
                "failed",
                "proof_does_not_reach_root",
                Some(seal_ref.to_string()),
            ));
        } else {
            if !disqualified_coverage_seals.contains(seal_ref) {
                seal_covered_records
                    .entry(seal_ref.to_string())
                    .or_default()
                    .insert(rec_ref.to_string());
            }
            findings.push(Finding::new(
                3,
                rec_ref,
                "membership",
                "ok",
                "ok",
                Some(seal_ref.to_string()),
            ));
        }
    }

    // §6.3b: Deployment start, root changes, and chain pinning (Amendment A6 Slice 1 & Slice 2).
    let start_eval = start::evaluate_start(
        &opened_records,
        &opened_by_ref,
        &any_sig_failed_by_idx,
        &body_result_by_idx,
        &seal_covered_records,
        opts,
    );
    findings.extend(start_eval.findings);

    // §6.3a / §6.3b / A7 §3: Authority from trusted roots (A5) or pinned chain (A6).
    let a5_qualifying_seal_refs = if opts.trusted_roots.is_some() {
        authority::compute_authority_findings(
            &opened_records,
            &opened_by_ref,
            &any_sig_failed_by_idx,
            &body_result_by_idx,
            &multi_sig_mismatch_by_idx,
            &seal_covered_records,
            &start_eval.trusted_roots_tenures,
            &mut authority_ok_by_idx,
            &mut findings,
        )
    } else {
        match start_eval.pinned_outcome {
            PinnedChainOutcome::NotPinned => BTreeSet::new(),
            PinnedChainOutcome::Established(tenures) => authority::compute_authority_findings(
                &opened_records,
                &opened_by_ref,
                &any_sig_failed_by_idx,
                &body_result_by_idx,
                &multi_sig_mismatch_by_idx,
                &seal_covered_records,
                &tenures,
                &mut authority_ok_by_idx,
                &mut findings,
            ),
            PinnedChainOutcome::Incomplete => {
                if let Some(tc) = opts.trusted_chain.as_deref() {
                    authority::emit_incomplete_chain_authority_findings(
                        &opened_records,
                        tc,
                        &mut findings,
                    );
                }
                BTreeSet::new()
            }
            PinnedChainOutcome::Failed => authority::compute_authority_findings(
                &opened_records,
                &opened_by_ref,
                &any_sig_failed_by_idx,
                &body_result_by_idx,
                &multi_sig_mismatch_by_idx,
                &seal_covered_records,
                &[],
                &mut authority_ok_by_idx,
                &mut findings,
            ),
        }
    };

    // §6.4 / §6.4a (`A7` §§4–5): Content, scoped legal holds, releases, and payload disposition.
    retention::evaluate_content_findings(
        &opened_records,
        &opened_by_ref,
        &body_result_by_idx,
        &profile_bounds_ok_by_idx,
        &authority_ok_by_idx,
        base_defs,
        &valid_blobs,
        &omissions_by_ref,
        &seal_covered_records,
        &sealer_ok_seal_refs,
        &a5_qualifying_seal_refs,
        opts,
        &mut findings,
    );

    Report::from_findings_and_start(findings, start_eval.report_start)
}

fn has_multi_signer_count_mismatch(
    rec: &OpenedRecord,
    base_defs: &BaseDefinitions,
    opts: &VerifyOptions,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
) -> bool {
    let Some(schema_ref) = rec.payload.get("schemaRef").and_then(Value::as_str) else {
        return false;
    };
    let Some(def_bytes) = obtain_definition_bytes(schema_ref, base_defs, opts, valid_blobs) else {
        return false;
    };
    let Some(parsed_def) = ParsedDefinition::parse(def_bytes) else {
        return false;
    };
    parsed_def.signatures > 1 && rec.signers.len() != parsed_def.signatures
}

fn obtain_definition_bytes<'a>(
    schema_ref: &str,
    base_defs: &'a BaseDefinitions,
    opts: &'a VerifyOptions,
    valid_blobs: &'a BTreeMap<String, Vec<u8>>,
) -> Option<&'a [u8]> {
    if let Some(b) = base_defs.get_bytes(schema_ref) {
        return Some(b);
    }
    if let Some(b) = opts.installed_definitions.get(schema_ref)
        && bytes_ref_of(b) == schema_ref
    {
        return Some(b.as_slice());
    }
    if let Some(b) = valid_blobs.get(schema_ref)
        && bytes_ref_of(b) == schema_ref
    {
        return Some(b.as_slice());
    }
    None
}

fn check_record_body(
    rec: &OpenedRecord,
    base_defs: &BaseDefinitions,
    opts: &VerifyOptions,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
) -> Finding {
    // 1. Validate against `schemas/evidence-envelope.schema.json`.
    // Note: in `evidence-envelope.schema.json`, `causes` has `uniqueItems: true`;
    // wait — check if duplicate `causes` should fail step 1 (`envelope_does_not_match_schema`)
    // or step 2 (`causes_not_sorted_and_unique`)! Step 1 literally runs `evidence-envelope.schema.json` first.
    if !validate_wire_schema(WireSchemaKind::EvidenceEnvelope, &rec.payload) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "failed",
            "envelope_does_not_match_schema",
            None,
        );
    }

    // 2. If `causes` is present, sorted by byte order and no duplicates.
    if let Some(causes_val) = rec.payload.get("causes") {
        let Some(causes_arr) = causes_val.as_array() else {
            return Finding::new(
                2,
                &rec.rec_ref,
                "body",
                "failed",
                "causes_not_sorted_and_unique",
                None,
            );
        };
        let mut prev_cause: Option<&[u8]> = None;
        for c in causes_arr {
            let Some(cs) = c.as_str() else {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "body",
                    "failed",
                    "causes_not_sorted_and_unique",
                    None,
                );
            };
            if let Some(prev) = prev_cause
                && prev >= cs.as_bytes()
            {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "body",
                    "failed",
                    "causes_not_sorted_and_unique",
                    None,
                );
            }
            prev_cause = Some(cs.as_bytes());
        }
    }

    // 3. Body against its definition (§6.2).
    let schema_ref = rec.payload["schemaRef"]
        .as_str()
        .expect("evidence-envelope schema");
    let kind_path = rec.kind_path().expect("evidence-envelope schema");

    let Some(def_bytes) = obtain_definition_bytes(schema_ref, base_defs, opts, valid_blobs) else {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "incomplete",
            "definition_not_available",
            Some(schema_ref.to_string()),
        );
    };

    let Some(parsed_def) = ParsedDefinition::parse(def_bytes) else {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "incomplete",
            "definition_not_available",
            Some(schema_ref.to_string()),
        );
    };

    if parsed_def.kind != kind_path {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "failed",
            "definition_is_for_another_kind",
            None,
        );
    }

    if rec.signers.len() != parsed_def.signatures {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "failed",
            "signature_count_differs_from_definition",
            None,
        );
    }

    if !parsed_def.validate_body(&rec.payload["body"], &rec.signers) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "failed",
            "body_does_not_match_definition",
            None,
        );
    }

    // 4. `SessionOpened` / `SessionClosed` session equality.
    let bare_kind = rec.payload["kind"]
        .as_str()
        .expect("evidence-envelope schema");
    if (bare_kind == "SessionOpened" || bare_kind == "SessionClosed")
        && let (Some(env_session), Some(body_session)) = (
            rec.payload.get("session"),
            rec.payload["body"].get("session"),
        )
        && env_session != body_session
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "body",
            "failed",
            "session_differs_from_body",
            None,
        );
    }

    Finding::new(2, &rec.rec_ref, "body", "ok", "ok", Some(kind_path))
}

fn check_record_publication(
    rec: &OpenedRecord,
    published_statements: &[PublishedStatement],
    publisher_trust: &PublisherTrust,
) -> Finding {
    let kind_path = rec.kind_path().unwrap_or_default();
    if kind_path == "provenance.r5e.io/v2/DefinitionPublished" {
        let issuer = &rec.signers[0];
        let believed_for_all_listed = publisher_trust.contains_publisher(issuer)
            && rec
                .payload
                .get("body")
                .and_then(|b| b.get("definitions"))
                .and_then(Value::as_array)
                .is_none_or(|defs| {
                    defs.iter().all(|item| {
                        item.get("kind")
                            .and_then(Value::as_str)
                            .is_none_or(|k| publisher_trust.believes(issuer, k))
                    })
                });
        if !believed_for_all_listed {
            return Finding::new(
                2,
                &rec.rec_ref,
                "publication",
                "incomplete",
                "publisher_not_trusted",
                Some(rec.rec_ref.clone()),
            );
        }
    }

    let schema_ref_opt = rec
        .payload
        .get("schemaRef")
        .and_then(Value::as_str)
        .map(str::to_string);

    let stmts_for_kind: Vec<&PublishedStatement> = published_statements
        .iter()
        .filter(|s| s.kind_path == kind_path)
        .collect();

    if let Some(trusted_match) = stmts_for_kind.iter().find(|s| {
        publisher_trust.believes(&s.issuer, &kind_path)
            && schema_ref_opt.as_deref() == Some(s.definition_ref.as_str())
    }) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "ok",
            "ok",
            Some(trusted_match.pub_ref.clone()),
        );
    }

    if let Some(first_trusted) = stmts_for_kind
        .iter()
        .find(|s| publisher_trust.believes(&s.issuer, &kind_path))
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "failed",
            "definition_differs_from_published",
            Some(first_trusted.pub_ref.clone()),
        );
    }

    if let Some(untrusted_match) = stmts_for_kind.iter().find(|s| {
        !publisher_trust.believes(&s.issuer, &kind_path)
            && schema_ref_opt.as_deref() == Some(s.definition_ref.as_str())
    }) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "incomplete",
            "publisher_not_trusted",
            Some(untrusted_match.pub_ref.clone()),
        );
    }

    Finding::new(
        2,
        &rec.rec_ref,
        "publication",
        "incomplete",
        "publication_not_carried",
        schema_ref_opt,
    )
}

fn check_record_profile(
    rec: &OpenedRecord,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
    trusted_profiles: &BTreeSet<String>,
    emit_profile_authority: bool,
    findings: &mut Vec<Finding>,
) -> (bool, bool) {
    let profile_ref_opt = rec.payload.get("profileRef").and_then(Value::as_str);
    let Some(profile_bytes) = profile_ref_opt.and_then(|pr| valid_blobs.get(pr)) else {
        findings.push(Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "incomplete",
            "profile_not_available",
            profile_ref_opt.map(str::to_string),
        ));
        return (false, false);
    };

    let pref_str = profile_ref_opt.unwrap().to_string();
    let Some(prof_val) = parse_canonical_json(profile_bytes)
        .filter(|pv| pv.is_object() && validate_wire_schema(WireSchemaKind::CaptureProfile, pv))
    else {
        findings.push(Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "failed",
            "unreadable_profile",
            Some(pref_str),
        ));
        return (false, false);
    };

    let kind_path = rec.kind_path().unwrap_or_default();
    let schema_ref = rec.payload.get("schemaRef").and_then(Value::as_str);
    let rec_stream = rec.payload.get("stream").and_then(Value::as_str);
    let rec_actor = rec.payload.get("actor").and_then(Value::as_str);
    let rec_issuer = rec.signers[0].as_str();

    let policy_required = prof_val["policyRequiredKinds"]
        .as_array()
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(kind_path.as_str())));

    let bounds_finding = if schema_ref.is_none()
        || prof_val["schemas"].get(&kind_path).and_then(Value::as_str) != schema_ref
    {
        Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "failed",
            "kind_not_in_profile",
            Some(pref_str.clone()),
        )
    } else if !has_matching_issuer_binding(
        &prof_val["authority"]["bindings"],
        rec_stream,
        rec_actor,
        rec_issuer,
    ) {
        Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "failed",
            "issuer_not_bound",
            Some(pref_str.clone()),
        )
    } else if policy_required
        && !rec
            .payload
            .get("body")
            .and_then(|b| b.get("policy"))
            .is_some_and(Value::is_object)
    {
        Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "failed",
            "policy_required",
            Some(pref_str.clone()),
        )
    } else {
        Finding::new(
            2,
            &rec.rec_ref,
            "profile_bounds",
            "ok",
            "ok",
            Some(pref_str.clone()),
        )
    };
    let bounds_ok = bounds_finding.result == "ok";
    findings.push(bounds_finding);

    let mut prof_auth_ok = false;
    if emit_profile_authority {
        if trusted_profiles.contains(&pref_str) {
            prof_auth_ok = true;
            findings.push(Finding::new(
                2,
                &rec.rec_ref,
                "authority",
                "ok",
                "ok",
                Some(pref_str),
            ));
        } else {
            findings.push(Finding::new(
                2,
                &rec.rec_ref,
                "authority",
                "incomplete",
                "profile_not_trusted",
                Some(pref_str),
            ));
        }
    }
    (bounds_ok, prof_auth_ok)
}

fn check_seal_epoch(
    seal_rec: &OpenedRecord,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
) -> (Finding, Option<Vec<String>>) {
    let seal_ref = &seal_rec.rec_ref;
    let seal_body = seal_rec.payload.get("body").unwrap_or(&json!(null));
    let manifest_ref_opt = seal_body.get("manifestRef").and_then(Value::as_str);

    let Some(manifest_bytes) = manifest_ref_opt.and_then(|mr| valid_blobs.get(mr)) else {
        return (
            Finding::new(
                3,
                seal_ref,
                "epoch",
                "incomplete",
                "manifest_not_carried",
                manifest_ref_opt.map(str::to_string),
            ),
            None,
        );
    };

    let mref_str = manifest_ref_opt.unwrap().to_string();
    let Some(manifest_val) = parse_canonical_json(manifest_bytes)
        .filter(|mv| validate_wire_schema(WireSchemaKind::EpochManifest, mv))
    else {
        return (
            Finding::new(
                3,
                seal_ref,
                "epoch",
                "failed",
                "unreadable_manifest",
                Some(mref_str),
            ),
            None,
        );
    };

    let events_arr = manifest_val["events"]
        .as_array()
        .expect("epoch-manifest schema");
    if events_arr
        .iter()
        .any(|ev| ev.as_str().is_none_or(|er| !opened_by_ref.contains_key(er)))
    {
        return (
            Finding::new(
                3,
                seal_ref,
                "epoch",
                "incomplete",
                "not_every_covered_record_is_carried",
                None,
            ),
            None,
        );
    }

    if manifest_val.get("format").and_then(Value::as_str) != Some("r5e.provenance-epoch/v2") {
        return (
            Finding::new(
                3,
                seal_ref,
                "epoch",
                "failed",
                "epoch_manifest_format",
                None,
            ),
            None,
        );
    }

    let manifest_hash_matches = encode_canonical_json(&manifest_val)
        .is_some_and(|enc| bytes_ref_of(enc.as_bytes()) == mref_str);
    if !manifest_hash_matches {
        return (
            Finding::new(3, seal_ref, "epoch", "failed", "epoch_manifest_ref", None),
            None,
        );
    }

    let first_seq_opt = seal_body.get("firstSeq").and_then(parse_v2_integer);
    let last_seq_opt = seal_body.get("lastSeq").and_then(parse_v2_integer);
    let (Some(first_seq), Some(last_seq)) = (first_seq_opt, last_seq_opt) else {
        return (
            Finding::new(3, seal_ref, "epoch", "failed", "epoch_range_length", None),
            None,
        );
    };
    if (last_seq as i128) - (first_seq as i128) + 1 != (events_arr.len() as i128) {
        return (
            Finding::new(3, seal_ref, "epoch", "failed", "epoch_range_length", None),
            None,
        );
    }

    let mut leaf_digests: Vec<[u8; 32]> = Vec::with_capacity(events_arr.len());
    for ev in events_arr {
        let er = ev.as_str().expect("epoch-manifest schema");
        let Some(d) = er.strip_prefix("evidence:sha256:").and_then(decode_hex_32) else {
            return (
                Finding::new(3, seal_ref, "epoch", "failed", "epoch_root", None),
                None,
            );
        };
        leaf_digests.push(d);
    }
    let computed_root = format!("sha256:{}", hex_encode(&merkle_root(&leaf_digests)));
    if seal_body.get("root").and_then(Value::as_str) != Some(computed_root.as_str()) {
        return (
            Finding::new(3, seal_ref, "epoch", "failed", "epoch_root", None),
            None,
        );
    }

    let sealed_stream = seal_body.get("stream").and_then(Value::as_str);
    let mut covered_events: Vec<String> = Vec::with_capacity(events_arr.len());
    for (idx, ev) in events_arr.iter().enumerate() {
        let er = ev.as_str().expect("epoch-manifest schema");
        let cov = &opened_records[opened_by_ref[er]];

        if sealed_stream.is_none()
            || cov.payload.get("stream").and_then(Value::as_str) != sealed_stream
        {
            return (
                Finding::new(3, seal_ref, "epoch", "failed", "epoch_stream", None),
                None,
            );
        }

        let expected_seq = (first_seq as i128) + (idx as i128);
        if cov
            .payload
            .get("seq")
            .and_then(parse_v2_integer)
            .map(|s| s as i128)
            != Some(expected_seq)
        {
            return (
                Finding::new(3, seal_ref, "epoch", "failed", "epoch_sequence", None),
                None,
            );
        }

        if idx == 0 {
            if first_seq == 1 && !cov.payload.get("previous").is_some_and(Value::is_null) {
                return (
                    Finding::new(3, seal_ref, "epoch", "failed", "epoch_previous", None),
                    None,
                );
            }
        } else {
            let prev_ref = events_arr[idx - 1].as_str().expect("epoch-manifest schema");
            if cov.payload.get("previous").and_then(Value::as_str) != Some(prev_ref) {
                return (
                    Finding::new(3, seal_ref, "epoch", "failed", "epoch_previous", None),
                    None,
                );
            }
        }
        covered_events.push(er.to_string());
    }

    (
        Finding::new(
            3,
            seal_ref,
            "epoch",
            "ok",
            "ok",
            Some(format!("seq:{first_seq}-{last_seq}")),
        ),
        Some(covered_events),
    )
}

fn check_seal_chain(
    seal_rec: &OpenedRecord,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
) -> Option<Finding> {
    let seal_ref = &seal_rec.rec_ref;
    let seal_body = seal_rec.payload.get("body").unwrap_or(&json!(null));
    let first_seq = seal_body.get("firstSeq").and_then(parse_v2_integer)?;
    let prev_val = seal_body.get("previousSeal").filter(|v| !v.is_null());

    if first_seq == 1 {
        if prev_val.is_some() {
            return Some(Finding::new(
                3,
                seal_ref,
                "seal_chain",
                "failed",
                "first_seal_names_a_predecessor",
                None,
            ));
        }
        return None;
    }

    if first_seq > 1 {
        let Some(prev_v) = prev_val else {
            return Some(Finding::new(
                3,
                seal_ref,
                "seal_chain",
                "failed",
                "seal_predecessor_missing",
                None,
            ));
        };
        let prev_ref = prev_v.as_str()?;
        let &prev_idx = opened_by_ref.get(prev_ref)?;
        let prev_rec = &opened_records[prev_idx];
        let prev_body = prev_rec.payload.get("body").unwrap_or(&json!(null));
        let cur_stream = seal_body.get("stream").and_then(Value::as_str);
        let prev_stream = prev_body.get("stream").and_then(Value::as_str);
        let prev_last_seq = prev_body.get("lastSeq").and_then(parse_v2_integer);

        let adjoins = prev_rec.kind_path().as_deref() == Some("provenance.r5e.io/v2/EpochSeal")
            && cur_stream.is_some()
            && cur_stream == prev_stream
            && prev_last_seq == Some(first_seq - 1);

        if adjoins {
            return Some(Finding::new(
                3,
                seal_ref,
                "seal_chain",
                "ok",
                "ok",
                Some(prev_ref.to_string()),
            ));
        } else {
            return Some(Finding::new(
                3,
                seal_ref,
                "seal_chain",
                "failed",
                "seal_predecessor_does_not_adjoin",
                Some(prev_ref.to_string()),
            ));
        }
    }

    None
}
