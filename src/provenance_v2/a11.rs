use super::canonical::{
    UtcInstant, bytes_ref_of, ct_eq_str, decode_base64, decode_strict_base64,
    encode_canonical_json, is_bytes_ref, is_salted_bytes_ref, is_valid_utc_z_datetime,
    parse_canonical_json, parse_rfc3339_instant, parse_v2_integer, salted_bytes_ref_of,
};
use super::crypto::{compute_keyid, verify_signature};
use super::wire_schema::A11_EXPORT_MEMBERS;
use super::{
    AvailableKey, BaseDefinitions, Finding, OpenedRecord, REPORT_FORMAT_V2, Report,
    TrustedCheckpoint,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const AMENDMENT_A11: &str = "A11";

const KIND_BASIS: &str = "provenance.r5e.io/v2/Basis";
const KIND_BASIS_OVERLAY: &str = "provenance.r5e.io/v2/BasisOverlay";
const KIND_RELEASE_REQUEST: &str = "provenance.r5e.io/v2/ReleaseRequest";
const KIND_RELEASE_RECEIPT: &str = "provenance.r5e.io/v2/ReleaseReceipt";
const KIND_ERASURE_ANSWER: &str = "provenance.r5e.io/v2/ErasureAnswer";
const KIND_SUCCESSION: &str = "provenance.r5e.io/v2/Succession";
const KIND_ENDORSEMENT: &str = "provenance.r5e.io/v2/Endorsement";
const KIND_REVOCATION: &str = "provenance.r5e.io/v2/Revocation";
const KIND_DEPLOYMENT: &str = "provenance.r5e.io/v2/Deployment";
const KIND_ROOTS_CHANGED: &str = "provenance.r5e.io/v2/RootsChanged";
const KIND_DISCLOSURE: &str = "provenance.r5e.io/v2/Disclosure";
const KIND_RETENTION_HOLD: &str = "provenance.r5e.io/v2/RetentionHold";
const KIND_CHECKPOINT: &str = "provenance.r5e.io/v2/Checkpoint";
const KIND_DEFINITION_PUBLISHED: &str = "provenance.r5e.io/v2/DefinitionPublished";
const KIND_SESSION_OPENED: &str = "provenance.r5e.io/v2/SessionOpened";
const KIND_SESSION_CLOSED: &str = "provenance.r5e.io/v2/SessionClosed";

const A11_ROOT_KINDS: [&str; 5] = [
    "Basis",
    "BasisOverlay",
    "ReleaseRequest",
    "ReleaseReceipt",
    "ErasureAnswer",
];

const A11_EXTENDED_FIELDS: [&str; 17] = [
    "custodyLevel",
    "recoveryProof",
    "hardwareAttestationRef",
    "erasureAnswerRef",
    "releaseRequestRef",
    "releaseReceiptRef",
    "recoveryRule",
    "signerKind",
    "keyStorage",
    "basisRef",
    "reviewAt",
    "sealedServiceCopies",
    "approverRoles",
    "witnessKeys",
    "overseerKey",
    "allowedMeasurements",
    "hardwareAttestationRoots",
];

const V10C_EXCLUDED_KINDS: [&str; 16] = [
    "provenance.r5e.io/v2/DefinitionPublished",
    "provenance.r5e.io/v2/Deployment",
    "provenance.r5e.io/v2/ChainStarted",
    "provenance.r5e.io/v2/RootsChanged",
    "provenance.r5e.io/v2/RootChangeApproval",
    "provenance.r5e.io/v2/Endorsement",
    "provenance.r5e.io/v2/Succession",
    "provenance.r5e.io/v2/Revocation",
    "provenance.r5e.io/v2/Checkpoint",
    "provenance.r5e.io/v2/EpochSeal",
    "provenance.r5e.io/v2/Basis",
    "provenance.r5e.io/v2/BasisOverlay",
    "provenance.r5e.io/v2/ReleaseRequest",
    "provenance.r5e.io/v2/ReleaseReceipt",
    "provenance.r5e.io/v2/ErasureAnswer",
    "provenance.r5e.io/v2/Disclosure",
];

const DOMAIN_RELEASE_APPROVAL: &[u8] = b"r5e-release-approval-v1\0";
const DOMAIN_HW_ATTESTATION: &[u8] = b"r5e-hw-attestation-v1\0";
const DOMAIN_WITNESS_RECEIPT: &[u8] = b"r5e-witness-receipt-v1\0";
const DOMAIN_SUCCESSION_RECOVERY: &[u8] = b"r5e-succession-recovery-v1\0";
const DOMAIN_ERASURE_PROOF: &[u8] = b"r5e-erasure-proof-v1\0";

const MAX_APPROVALS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    CryptographicProof,
    MechanicalCheck,
    InstitutionalAssertion,
    UnavailableEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A11Finding {
    pub layer: u8,
    pub subject: String,
    pub check: String,
    pub result: String,
    pub code: String,
    pub category: FindingCategory,
    pub about: Option<String>,
}

impl A11Finding {
    pub fn new(
        layer: u8,
        subject: impl Into<String>,
        check: impl Into<String>,
        result: impl Into<String>,
        code: impl Into<String>,
        category: FindingCategory,
        about: Option<String>,
    ) -> Self {
        Self {
            layer,
            subject: subject.into(),
            check: check.into(),
            result: result.into(),
            code: code.into(),
            category,
            about,
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("A11Finding serializes to JSON Value")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedFinding {
    pub layer: u8,
    pub subject: String,
    pub check: String,
    pub result: String,
    pub code: String,
    pub category: FindingCategory,
    pub about: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct A11Summary {
    pub ok: usize,
    pub failed: usize,
    pub incomplete: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct A11CategoryCounts {
    pub cryptographic_proof: usize,
    pub mechanical_check: usize,
    pub institutional_assertion: usize,
    pub unavailable_evidence: usize,
}

impl A11CategoryCounts {
    fn bump(&mut self, cat: FindingCategory) {
        match cat {
            FindingCategory::CryptographicProof => self.cryptographic_proof += 1,
            FindingCategory::MechanicalCheck => self.mechanical_check += 1,
            FindingCategory::InstitutionalAssertion => self.institutional_assertion += 1,
            FindingCategory::UnavailableEvidence => self.unavailable_evidence += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A11BaselineSection {
    pub findings: Vec<ClassifiedFinding>,
    pub summary: A11Summary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A11Report {
    pub format: String,
    pub amendment: String,
    pub verdict: String,
    pub summary: A11Summary,
    pub categories: A11CategoryCounts,
    pub baseline: A11BaselineSection,
    pub a11_findings: Vec<A11Finding>,
}

impl A11Report {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("A11Report serializes to JSON Value")
    }

    pub fn to_canonical_json(&self) -> String {
        encode_canonical_json(&self.to_value()).expect("A11Report encodes as canonical JSON")
    }

    pub fn exit_code(&self, allow_incomplete: bool) -> i32 {
        match self.verdict.as_str() {
            "failed" => 1,
            "incomplete" => {
                if allow_incomplete {
                    0
                } else {
                    3
                }
            }
            _ => 0,
        }
    }
}

/// Detects whether a parsed export bundle uses any Amendment A11 feature
/// (A11 top-level member, A11 record kind, A11 extended field, or salted
/// content reference).
pub fn is_a11_bundle(bundle: &Value) -> bool {
    let Some(obj) = bundle.as_object() else {
        return false;
    };
    if A11_EXPORT_MEMBERS.iter().any(|k| obj.contains_key(*k)) {
        return true;
    }
    let Some(records) = obj.get("records").and_then(Value::as_array) else {
        return false;
    };
    for rec in records {
        let Some(payload_b64) = rec
            .get("envelope")
            .and_then(|e| e.get("payload"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(raw) = decode_base64(payload_b64) else {
            continue;
        };
        let Some(payload) = parse_canonical_json(&raw) else {
            continue;
        };
        if payload.get("apiVersion").and_then(Value::as_str) == Some("provenance.r5e.io/v2")
            && let Some(kind) = payload.get("kind").and_then(Value::as_str)
            && A11_ROOT_KINDS.contains(&kind)
        {
            return true;
        }
        if let Some(body) = payload.get("body") {
            if let Some(bmap) = body.as_object()
                && A11_EXTENDED_FIELDS.iter().any(|f| bmap.contains_key(*f))
            {
                return true;
            }
            if contains_salted_ref(body) {
                return true;
            }
        }
    }
    false
}

fn contains_salted_ref(val: &Value) -> bool {
    match val {
        Value::String(s) => is_salted_bytes_ref(s),
        Value::Array(items) => items.iter().any(contains_salted_ref),
        Value::Object(map) => map.values().any(contains_salted_ref),
        _ => false,
    }
}

/// Classifies any baseline Provenance v2 finding into one of the four A11 categories.
pub fn classify_finding(finding: &Finding) -> FindingCategory {
    if finding.result == "incomplete" {
        if matches!(
            finding.code.as_str(),
            "publisher_not_trusted" | "profile_not_trusted" | "time_rests_on_the_signer"
        ) {
            return FindingCategory::InstitutionalAssertion;
        }
        return FindingCategory::UnavailableEvidence;
    }
    match finding.check.as_str() {
        "identity" | "signature" | "content" | "content_hash" | "membership" | "epoch"
        | "merkle" => FindingCategory::CryptographicProof,
        _ => FindingCategory::MechanicalCheck,
    }
}

#[derive(Debug, Clone, Default)]
struct DeploymentContract {
    custody_level: Option<i64>,
    witness_keys: BTreeSet<String>,
    approver_roles: BTreeMap<String, BTreeSet<String>>,
    sealed_service_copies: BTreeMap<String, String>,
    hardware_attestation_roots: BTreeSet<String>,
    deployment_roots: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct ContractSnapshot {
    captured_at: Option<UtcInstant>,
    contract: DeploymentContract,
}

#[derive(Debug, Default)]
struct ContractHistory {
    by_ref: BTreeMap<String, DeploymentContract>,
    snapshots: Vec<ContractSnapshot>,
    latest: DeploymentContract,
    all_deployment_roots: BTreeSet<String>,
    all_approver_keys: BTreeSet<String>,
}

impl ContractHistory {
    fn build(opened_records: &[OpenedRecord]) -> Self {
        let mut contract_recs: Vec<&OpenedRecord> = opened_records
            .iter()
            .filter(|rec| {
                rec.all_sigs_ok
                    && matches!(
                        rec.kind_path().as_deref(),
                        Some(KIND_DEPLOYMENT | KIND_ROOTS_CHANGED)
                    )
            })
            .collect();
        contract_recs.sort_by(|a, b| {
            let sa = a.payload.get("seq").and_then(parse_v2_integer).unwrap_or(0);
            let sb = b.payload.get("seq").and_then(parse_v2_integer).unwrap_or(0);
            sa.cmp(&sb)
                .then_with(|| a.rec_ref.as_bytes().cmp(b.rec_ref.as_bytes()))
        });

        let mut running = DeploymentContract::default();
        let mut history = Self::default();

        for rec in contract_recs {
            let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
                continue;
            };
            if let Some(level) = body.get("custodyLevel").and_then(parse_v2_integer) {
                running.custody_level = Some(level);
            }
            if let Some(roots) = body.get("roots").and_then(Value::as_array) {
                let mut rset = BTreeSet::new();
                for r in roots {
                    if let Some(k) = r.get("key").and_then(Value::as_str) {
                        rset.insert(k.to_string());
                        history.all_deployment_roots.insert(k.to_string());
                    }
                }
                if !rset.is_empty() {
                    running.deployment_roots = rset;
                }
            }
            if let Some(wkeys) = body.get("witnessKeys").and_then(Value::as_array) {
                running.witness_keys = wkeys
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
            if let Some(aroles) = body.get("approverRoles").and_then(Value::as_array) {
                let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                for entry in aroles {
                    if let (Some(role), Some(keys)) = (
                        entry.get("role").and_then(Value::as_str),
                        entry.get("keys").and_then(Value::as_array),
                    ) {
                        let set: BTreeSet<String> = keys
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect();
                        for k in &set {
                            history.all_approver_keys.insert(k.clone());
                        }
                        map.insert(role.to_string(), set);
                    }
                }
                running.approver_roles = map;
            }
            if let Some(copies) = body.get("sealedServiceCopies").and_then(Value::as_array) {
                let mut cmap: BTreeMap<String, String> = BTreeMap::new();
                for entry in copies {
                    if let (Some(cid), Some(kid)) = (
                        entry.get("copyId").and_then(Value::as_str),
                        entry.get("keyId").and_then(Value::as_str),
                    ) && !cid.is_empty()
                        && !kid.is_empty()
                    {
                        cmap.insert(cid.to_string(), kid.to_string());
                    }
                }
                running.sealed_service_copies = cmap;
            }
            if let Some(hw_roots) = body
                .get("hardwareAttestationRoots")
                .and_then(Value::as_array)
            {
                running.hardware_attestation_roots = hw_roots
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }

            let captured_at = rec
                .payload
                .get("capturedAt")
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339_instant(s, None, false));
            history.by_ref.insert(rec.rec_ref.clone(), running.clone());
            history.snapshots.push(ContractSnapshot {
                captured_at,
                contract: running.clone(),
            });
        }

        history.latest = running;
        history
    }

    fn resolve(
        &self,
        contract_version: Option<&str>,
        at_time: Option<&UtcInstant>,
    ) -> &DeploymentContract {
        if let Some(cv) = contract_version
            && let Some(c) = self.by_ref.get(cv)
        {
            return c;
        }
        if let Some(t) = at_time {
            let mut best: Option<&DeploymentContract> = None;
            for snap in &self.snapshots {
                if snap.captured_at.as_ref().is_some_and(|st| st <= t) {
                    best = Some(&snap.contract);
                }
            }
            if let Some(c) = best {
                return c;
            }
        }
        &self.latest
    }
}

fn verify_embedded_signature(
    keyid: &str,
    sig_b64: &str,
    domain: &[u8],
    payload_obj: &Value,
    available_keys: &BTreeMap<String, AvailableKey>,
) -> bool {
    let Some(akey) = available_keys.get(keyid) else {
        return false;
    };
    let Some(derived) = compute_keyid(&akey.algorithm, &akey.bytes) else {
        return false;
    };
    if !ct_eq_str(&derived, keyid) {
        return false;
    }
    let Some(sig_bytes) = decode_strict_base64(sig_b64) else {
        return false;
    };
    let Some(canon) = encode_canonical_json(payload_obj) else {
        return false;
    };
    let mut msg = Vec::with_capacity(domain.len() + canon.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(canon.as_bytes());
    verify_signature(&akey.algorithm, &akey.bytes, &sig_bytes, &msg)
}

fn record_sort_key(rec: &OpenedRecord) -> (Option<UtcInstant>, i64, &str) {
    let ts = rec
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false));
    let seq = rec
        .payload
        .get("seq")
        .and_then(parse_v2_integer)
        .unwrap_or(0);
    (ts, seq, rec.rec_ref.as_str())
}

fn collect_salted_refs(val: &Value, out: &mut BTreeSet<String>) {
    match val {
        Value::String(s) => {
            if is_salted_bytes_ref(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_salted_refs(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_salted_refs(v, out);
            }
        }
        _ => {}
    }
}

fn collect_plain_bytes_refs(val: &Value, out: &mut BTreeSet<String>) {
    match val {
        Value::String(s) => {
            if is_bytes_ref(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_plain_bytes_refs(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_plain_bytes_refs(v, out);
            }
        }
        _ => {}
    }
}

/// Pre-verifies every entry in `bundle.saltedContent` once and caches the result.
fn verify_all_salted_content(bundle: &Value) -> BTreeMap<String, Result<Vec<u8>, ()>> {
    let mut cache = BTreeMap::new();
    let Some(map) = bundle.get("saltedContent").and_then(Value::as_object) else {
        return cache;
    };
    for (s_ref, entry) in map {
        let verified = (|| -> Option<Vec<u8>> {
            let salt_b64 = entry.get("salt")?.as_str()?;
            let bytes_b64 = entry.get("bytes")?.as_str()?;
            let salt = decode_strict_base64(salt_b64)?;
            if salt.len() != 32 {
                return None;
            }
            let plaintext = decode_base64(bytes_b64)?;
            let expected = salted_bytes_ref_of(&salt, &plaintext);
            if ct_eq_str(&expected, s_ref) {
                Some(plaintext)
            } else {
                None
            }
        })();
        cache.insert(s_ref.clone(), verified.ok_or(()));
    }
    cache
}

fn load_carried_content<'a>(
    content_ref: &str,
    valid_blobs: &'a BTreeMap<String, Vec<u8>>,
    salted_cache: &'a BTreeMap<String, Result<Vec<u8>, ()>>,
) -> Option<&'a [u8]> {
    if let Some(raw) = valid_blobs.get(content_ref) {
        return Some(raw.as_slice());
    }
    if let Some(Ok(raw)) = salted_cache.get(content_ref) {
        return Some(raw.as_slice());
    }
    None
}

struct EndorsementIndex<'a> {
    by_subject: BTreeMap<String, Vec<(usize, &'a OpenedRecord)>>,
    revocations_by_target: BTreeMap<String, Vec<UtcInstant>>,
    all_issuer_keys: BTreeSet<String>,
}

impl<'a> EndorsementIndex<'a> {
    fn build(opened_records: &'a [OpenedRecord], body_result_by_idx: &[String]) -> Self {
        let mut by_subject: BTreeMap<String, Vec<(usize, &'a OpenedRecord)>> = BTreeMap::new();
        let mut revocations_by_target: BTreeMap<String, Vec<UtcInstant>> = BTreeMap::new();
        let mut all_issuer_keys: BTreeSet<String> = BTreeSet::new();

        for (idx, rec) in opened_records.iter().enumerate() {
            if !rec.all_sigs_ok || body_result_by_idx.get(idx).map(String::as_str) != Some("ok") {
                continue;
            }
            match rec.kind_path().as_deref() {
                Some(KIND_ENDORSEMENT) => {
                    if let Some(issuer) = rec.signers.first() {
                        all_issuer_keys.insert(issuer.clone());
                    }
                    if let Some(subj) = rec
                        .payload
                        .get("body")
                        .and_then(|b| b.get("subject"))
                        .and_then(Value::as_str)
                    {
                        by_subject
                            .entry(subj.to_string())
                            .or_default()
                            .push((idx, rec));
                    }
                }
                Some(KIND_REVOCATION) => {
                    if let (Some(target), Some(ts)) = (
                        rec.payload
                            .get("body")
                            .and_then(|b| b.get("target"))
                            .and_then(Value::as_str),
                        rec.payload
                            .get("capturedAt")
                            .and_then(Value::as_str)
                            .and_then(|s| parse_rfc3339_instant(s, None, false)),
                    ) {
                        revocations_by_target
                            .entry(target.to_string())
                            .or_default()
                            .push(ts);
                    }
                }
                _ => {}
            }
        }

        for list in by_subject.values_mut() {
            list.sort_by(|(_, a), (_, b)| record_sort_key(a).cmp(&record_sort_key(b)));
        }

        Self {
            by_subject,
            revocations_by_target,
            all_issuer_keys,
        }
    }

    fn is_revoked_at(&self, rec: &OpenedRecord, subject_key: &str, at_time: &UtcInstant) -> bool {
        if let Some(times) = self.revocations_by_target.get(&rec.rec_ref)
            && times.iter().any(|t| t <= at_time)
        {
            return true;
        }
        if let Some(times) = self.revocations_by_target.get(subject_key)
            && times.iter().any(|t| t <= at_time)
        {
            return true;
        }
        false
    }

    fn is_in_window(rec: &OpenedRecord, at_time: &UtcInstant) -> bool {
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            return false;
        };
        if let Some(nb) = body
            .get("notBefore")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
            && at_time < &nb
        {
            return false;
        }
        if let Some(na) = body
            .get("notAfter")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
            && at_time > &na
        {
            return false;
        }
        true
    }

    fn active_endorsements_at(
        &self,
        subject_key: &str,
        at_time: Option<&UtcInstant>,
        authority_ok_by_idx: Option<&[bool]>,
    ) -> Vec<&'a OpenedRecord> {
        let Some(list) = self.by_subject.get(subject_key) else {
            return Vec::new();
        };
        list.iter()
            .filter_map(|&(idx, rec)| {
                if let Some(auth_ok) = authority_ok_by_idx
                    && auth_ok.iter().any(|&b| b)
                    && !auth_ok.get(idx).copied().unwrap_or(false)
                {
                    return None;
                }
                if let Some(t) = at_time {
                    if !Self::is_in_window(rec, t) {
                        return None;
                    }
                    if self.is_revoked_at(rec, subject_key, t) {
                        return None;
                    }
                }
                Some(rec)
            })
            .collect()
    }

    fn latest_active_at(
        &self,
        subject_key: &str,
        at_time: Option<&UtcInstant>,
        authority_ok_by_idx: Option<&[bool]>,
    ) -> Option<&'a OpenedRecord> {
        self.active_endorsements_at(subject_key, at_time, authority_ok_by_idx)
            .into_iter()
            .last()
    }
}

/// Pre-computes the set of A11 recovery-form `Succession` record references whose
/// recovery proofs pass V7 verification, so baseline A5 `SuccessionIndex` never
/// admits an unverified or forged recovery succession.
pub(crate) fn collect_verified_recovery_successions(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    available_keys: &BTreeMap<String, AvailableKey>,
    base_defs: &BaseDefinitions,
) -> BTreeSet<String> {
    let body_all_ok = vec!["ok".to_string(); opened_records.len()];
    let history = ContractHistory::build(opened_records);
    let endorsements = EndorsementIndex::build(opened_records, &body_all_ok);
    let mut dummy_findings = Vec::new();
    eval_v7_succession_recovery_inner(
        opened_records,
        opened_by_ref,
        available_keys,
        base_defs,
        &history,
        &endorsements,
        &mut dummy_findings,
    )
}

pub(crate) struct A11EvalContext<'a> {
    pub bundle: &'a Value,
    pub opened_records: &'a [OpenedRecord],
    pub opened_by_ref: &'a BTreeMap<String, usize>,
    pub body_result_by_idx: &'a [String],
    pub authority_ok_by_idx: &'a [bool],
    pub available_keys: &'a BTreeMap<String, AvailableKey>,
    pub valid_blobs: &'a BTreeMap<String, Vec<u8>>,
    pub base_defs: &'a BaseDefinitions,
    pub trusted_checkpoints: &'a [TrustedCheckpoint],
    pub a11_active: bool,
}

pub(crate) fn evaluate_a11(ctx: &A11EvalContext<'_>, baseline: Report) -> A11Report {
    let mut findings: Vec<A11Finding> = Vec::new();

    let bundle_malformed = baseline
        .findings
        .iter()
        .any(|f| f.code == "malformed_bundle");

    if ctx.a11_active && !bundle_malformed {
        let history = ContractHistory::build(ctx.opened_records);
        let endorsements = EndorsementIndex::build(ctx.opened_records, ctx.body_result_by_idx);
        let salted_cache = verify_all_salted_content(ctx.bundle);

        // Pre-sort BasisOverlay records by basisRef once.
        let mut overlays_by_basis: BTreeMap<String, Vec<&OpenedRecord>> = BTreeMap::new();
        for rec in ctx.opened_records {
            if rec.kind_path().as_deref() == Some(KIND_BASIS_OVERLAY)
                && let Some(bref) = rec
                    .payload
                    .get("body")
                    .and_then(|b| b.get("basisRef"))
                    .and_then(Value::as_str)
            {
                overlays_by_basis
                    .entry(bref.to_string())
                    .or_default()
                    .push(rec);
            }
        }
        for list in overlays_by_basis.values_mut() {
            list.sort_by(|a, b| {
                let ta = a
                    .payload
                    .get("body")
                    .and_then(|x| x.get("effectiveAt"))
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false));
                let tb = b
                    .payload
                    .get("body")
                    .and_then(|x| x.get("effectiveAt"))
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false));
                ta.cmp(&tb)
                    .then_with(|| a.rec_ref.as_bytes().cmp(b.rec_ref.as_bytes()))
            });
        }

        // V1: basis_signatures (also yields set of valid Basis refs).
        let valid_basis_refs = eval_v1_basis_signatures(ctx, &endorsements, &mut findings);

        // V5: witness_receipt_binding (also yields verified witness logIndex map for V3 L2 ordering).
        let witness_log_index_by_ref =
            eval_v5_witness_receipt_binding(ctx, &history, &mut findings);

        // V2: basis_declared_power
        eval_v2_basis_declared_power(ctx, &valid_basis_refs, &mut findings);

        // V3: basis_overlay_order (independent pass from V2)
        eval_v3_basis_overlay_order(
            ctx,
            &endorsements,
            &overlays_by_basis,
            &witness_log_index_by_ref,
            &mut findings,
        );

        // V4: release_request_approvals
        eval_v4_release_request_approvals(
            ctx,
            &history,
            &endorsements,
            &salted_cache,
            &valid_basis_refs,
            &mut findings,
        );

        // V6: release_receipt_fingerprint
        eval_v6_release_receipt_fingerprint(ctx, &history, &mut findings);

        // V7: succession_recovery
        let _ = eval_v7_succession_recovery_inner(
            ctx.opened_records,
            ctx.opened_by_ref,
            ctx.available_keys,
            ctx.base_defs,
            &history,
            &endorsements,
            &mut findings,
        );

        // V8: erasure_l2_proof
        eval_v8_erasure_l2_proof(ctx, &history, &salted_cache, &mut findings);

        // V9: salted_content_ref
        eval_v9_salted_content_ref(ctx, &salted_cache, &mut findings);

        // V10: checkpoint_and_unlock_log
        eval_v10_checkpoint_and_unlock_log(ctx, &salted_cache, &mut findings);

        // V11: definition_coexistence
        eval_v11_definition_coexistence(ctx, &mut findings);
    }

    findings.sort_by(|a, b| {
        a.layer
            .cmp(&b.layer)
            .then_with(|| a.subject.as_bytes().cmp(b.subject.as_bytes()))
            .then_with(|| a.check.as_bytes().cmp(b.check.as_bytes()))
            .then_with(|| a.code.as_bytes().cmp(b.code.as_bytes()))
            .then_with(|| match (&a.about, &b.about) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(x), Some(y)) => x.as_bytes().cmp(y.as_bytes()),
            })
            .then_with(|| a.result.as_bytes().cmp(b.result.as_bytes()))
    });

    let mut categories = A11CategoryCounts::default();
    let mut baseline_findings = Vec::with_capacity(baseline.findings.len());
    for bf in &baseline.findings {
        let cat = classify_finding(bf);
        categories.bump(cat);
        baseline_findings.push(ClassifiedFinding {
            layer: bf.layer,
            subject: bf.subject.clone(),
            check: bf.check.clone(),
            result: bf.result.clone(),
            code: bf.code.clone(),
            category: cat,
            about: bf.about.clone(),
        });
    }

    let mut a11_ok = 0usize;
    let mut a11_failed = 0usize;
    let mut a11_incomplete = 0usize;
    for f in &findings {
        categories.bump(f.category);
        match f.result.as_str() {
            "ok" => a11_ok += 1,
            "failed" => a11_failed += 1,
            "incomplete" => a11_incomplete += 1,
            _ => {}
        }
    }

    let baseline_summary = A11Summary {
        ok: baseline.summary.ok,
        failed: baseline.summary.failed,
        incomplete: baseline.summary.incomplete,
        total: baseline.summary.ok + baseline.summary.failed + baseline.summary.incomplete,
    };
    let total_summary = A11Summary {
        ok: baseline_summary.ok + a11_ok,
        failed: baseline_summary.failed + a11_failed,
        incomplete: baseline_summary.incomplete + a11_incomplete,
        total: baseline_summary.total + a11_ok + a11_failed + a11_incomplete,
    };

    let verdict = if total_summary.failed > 0 {
        "failed"
    } else if total_summary.incomplete > 0 {
        "incomplete"
    } else {
        "ok"
    };

    A11Report {
        format: REPORT_FORMAT_V2.to_string(),
        amendment: AMENDMENT_A11.to_string(),
        verdict: verdict.to_string(),
        summary: total_summary,
        categories,
        baseline: A11BaselineSection {
            findings: baseline_findings,
            summary: baseline_summary,
        },
        a11_findings: findings,
    }
}

fn eval_v1_basis_signatures(
    ctx: &A11EvalContext<'_>,
    endorsements: &EndorsementIndex<'_>,
    findings: &mut Vec<A11Finding>,
) -> BTreeSet<String> {
    let mut valid_basis_refs = BTreeSet::new();

    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_BASIS) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let subjects: BTreeSet<&str> = body
            .get("subjects")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let representative = body
            .get("representative")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let institution = body.get("institution").and_then(Value::as_str);

        // Structural person-naming predicate (SPEC §1.1): subjects non-empty OR representative present.
        let names_person = !subjects.is_empty() || representative.is_some();

        let distinct_signers: Vec<&str> = {
            let set: BTreeSet<&str> = rec.signers.iter().map(String::as_str).collect();
            set.into_iter().collect()
        };

        let at_time = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false));

        if names_person {
            if distinct_signers.len() > 2 || rec.signers.len() > 2 {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "basis_signatures",
                    "failed",
                    "basis_unexpected_signature_count",
                    FindingCategory::MechanicalCheck,
                    None,
                ));
                continue;
            }
            if distinct_signers.len() != 2 || !rec.all_sigs_ok {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "basis_signatures",
                    "failed",
                    "basis_missing_counter_signature",
                    FindingCategory::MechanicalCheck,
                    None,
                ));
                continue;
            }

            let signer_covers_institution = |sk: &str| -> bool {
                let Some(inst) = institution else {
                    return false;
                };
                endorsements
                    .active_endorsements_at(sk, at_time.as_ref(), Some(ctx.authority_ok_by_idx))
                    .into_iter()
                    .any(|e| {
                        e.payload
                            .get("body")
                            .and_then(|b| b.get("actsFor"))
                            .and_then(Value::as_str)
                            == Some(inst)
                    })
            };

            let signer_person_kind = |sk: &str| -> Option<&str> {
                let active = endorsements.active_endorsements_at(
                    sk,
                    at_time.as_ref(),
                    Some(ctx.authority_ok_by_idx),
                );
                for e in active.into_iter().rev() {
                    let Some(ebody) = e.payload.get("body").and_then(Value::as_object) else {
                        continue;
                    };
                    let acts_for = ebody.get("actsFor").and_then(Value::as_str);
                    let covers_person = acts_for
                        .is_some_and(|af| subjects.contains(af) || representative == Some(af));
                    if !covers_person {
                        continue;
                    }
                    let skind = ebody.get("signerKind").and_then(Value::as_str);
                    if matches!(skind, Some("personal" | "device_session")) {
                        return skind;
                    }
                }
                None
            };

            let s0 = distinct_signers[0];
            let s1 = distinct_signers[1];
            let pair_kind = if signer_covers_institution(s0)
                && let Some(pk) = signer_person_kind(s1)
            {
                Some(pk)
            } else if signer_covers_institution(s1)
                && let Some(pk) = signer_person_kind(s0)
            {
                Some(pk)
            } else {
                None
            };

            match pair_kind {
                Some("personal") => {
                    valid_basis_refs.insert(rec.rec_ref.clone());
                    findings.push(A11Finding::new(
                        2,
                        &rec.rec_ref,
                        "basis_signatures",
                        "ok",
                        "ok",
                        FindingCategory::MechanicalCheck,
                        None,
                    ));
                }
                Some("device_session") => {
                    valid_basis_refs.insert(rec.rec_ref.clone());
                    findings.push(A11Finding::new(
                        2,
                        &rec.rec_ref,
                        "basis_signatures",
                        "ok",
                        "basis_person_signed_by_device_session",
                        FindingCategory::InstitutionalAssertion,
                        None,
                    ));
                }
                _ => {
                    findings.push(A11Finding::new(
                        2,
                        &rec.rec_ref,
                        "basis_signatures",
                        "failed",
                        "basis_invalid_signer_binding",
                        FindingCategory::MechanicalCheck,
                        None,
                    ));
                }
            }
        } else if distinct_signers.len() > 2 || rec.signers.len() > 2 {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "basis_signatures",
                "failed",
                "basis_unexpected_signature_count",
                FindingCategory::MechanicalCheck,
                None,
            ));
        } else if !distinct_signers.is_empty() && rec.all_sigs_ok {
            valid_basis_refs.insert(rec.rec_ref.clone());
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "basis_signatures",
                "ok",
                "ok",
                FindingCategory::MechanicalCheck,
                None,
            ));
        } else {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "basis_signatures",
                "failed",
                "basis_missing_counter_signature",
                FindingCategory::MechanicalCheck,
                None,
            ));
        }
    }

    valid_basis_refs
}

/// Resolves target subjects for a list of target strings (`evidence:sha256:...` or
/// `urn:r5e:session:...`). Returns `(resolved_subjects, missing_targets)`.
fn resolve_targets_subjects(
    ctx: &A11EvalContext<'_>,
    targets: &[&str],
) -> (BTreeSet<String>, Vec<String>) {
    let mut subjects = BTreeSet::new();
    let mut missing = Vec::new();

    for &t in targets {
        if let Some(&idx) = ctx.opened_by_ref.get(t) {
            collect_subjects_from_record(ctx, &ctx.opened_records[idx], &mut subjects);
            continue;
        }
        if t.starts_with("urn:r5e:session:") {
            let mut found_any = false;
            for rec in ctx.opened_records {
                let rec_sess = rec.payload.get("session").and_then(Value::as_str);
                let body_sess = rec
                    .payload
                    .get("body")
                    .and_then(|b| b.get("session"))
                    .and_then(Value::as_str);
                if rec_sess == Some(t)
                    || (rec.kind_path().as_deref() == Some(KIND_SESSION_OPENED)
                        && body_sess == Some(t))
                {
                    found_any = true;
                    collect_subjects_from_record(ctx, rec, &mut subjects);
                }
            }
            if !found_any {
                missing.push(t.to_string());
            }
            continue;
        }
        missing.push(t.to_string());
    }

    (subjects, missing)
}

fn collect_subjects_from_record(
    ctx: &A11EvalContext<'_>,
    rec: &OpenedRecord,
    out: &mut BTreeSet<String>,
) {
    if let Some(body) = rec.payload.get("body").and_then(Value::as_object) {
        if let Some(arr) = body.get("subjects").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str()
                    && !s.is_empty()
                {
                    out.insert(s.to_string());
                }
            }
        }
        if let Some(s) = body.get("subject").and_then(Value::as_str)
            && !s.is_empty()
            && !s.starts_with("key:")
        {
            out.insert(s.to_string());
        }
        if let Some(bref) = body.get("basisRef").and_then(Value::as_str)
            && let Some(&bidx) = ctx.opened_by_ref.get(bref)
            && ctx.opened_records[bidx].kind_path().as_deref() == Some(KIND_BASIS)
            && let Some(arr) = ctx.opened_records[bidx]
                .payload
                .get("body")
                .and_then(|b| b.get("subjects"))
                .and_then(Value::as_array)
        {
            for v in arr {
                if let Some(s) = v.as_str()
                    && !s.is_empty()
                {
                    out.insert(s.to_string());
                }
            }
        }
    }
    // Also inspect contextRefs (in body or envelope) for linked Basis records.
    for crefs in [
        rec.payload
            .get("body")
            .and_then(|b| b.get("contextRefs"))
            .and_then(Value::as_array),
        rec.payload.get("contextRefs").and_then(Value::as_array),
    ]
    .into_iter()
    .flatten()
    {
        for cv in crefs {
            if let Some(cref) = cv.as_str()
                && let Some(&cidx) = ctx.opened_by_ref.get(cref)
                && ctx.opened_records[cidx].kind_path().as_deref() == Some(KIND_BASIS)
                && let Some(arr) = ctx.opened_records[cidx]
                    .payload
                    .get("body")
                    .and_then(|b| b.get("subjects"))
                    .and_then(Value::as_array)
            {
                for v in arr {
                    if let Some(s) = v.as_str()
                        && !s.is_empty()
                    {
                        out.insert(s.to_string());
                    }
                }
            }
        }
    }
}

struct ActBasisLink<'a> {
    basis_ref: &'a str,
    ground_id: Option<&'a str>,
    power: &'a str,
    targets: Vec<&'a str>,
    is_retention_hold: bool,
    review_at_present: bool,
    time_window_not_after: Option<UtcInstant>,
}

fn resolve_act_basis_link<'a>(
    ctx: &'a A11EvalContext<'a>,
    rec: &'a OpenedRecord,
) -> Option<ActBasisLink<'a>> {
    let kp = rec.kind_path()?;
    let body = rec.payload.get("body")?.as_object()?;
    match kp.as_str() {
        KIND_RELEASE_REQUEST => {
            let basis_ref = body.get("basisRef")?.as_str()?;
            let ground_id = body.get("groundId").and_then(Value::as_str);
            let power = body
                .get("power")
                .and_then(Value::as_str)
                .unwrap_or("disclose");
            let targets = body
                .get("targets")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let not_after = body
                .get("timeWindow")
                .and_then(|tw| tw.get("notAfter"))
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339_instant(s, None, false));
            Some(ActBasisLink {
                basis_ref,
                ground_id,
                power,
                targets,
                is_retention_hold: false,
                review_at_present: true,
                time_window_not_after: not_after,
            })
        }
        KIND_DISCLOSURE => {
            if let Some(rr_ref) = body.get("releaseRequestRef").and_then(Value::as_str) {
                let &rr_idx = ctx.opened_by_ref.get(rr_ref)?;
                let rr_rec = &ctx.opened_records[rr_idx];
                if rr_rec.kind_path().as_deref() != Some(KIND_RELEASE_REQUEST) {
                    return None;
                }
                let rr_body = rr_rec.payload.get("body")?.as_object()?;
                let basis_ref = rr_body.get("basisRef")?.as_str()?;
                let ground_id = rr_body.get("groundId").and_then(Value::as_str);
                let power = rr_body
                    .get("power")
                    .and_then(Value::as_str)
                    .unwrap_or("disclose");
                let targets = rr_body
                    .get("targets")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                return Some(ActBasisLink {
                    basis_ref,
                    ground_id,
                    power,
                    targets,
                    is_retention_hold: false,
                    review_at_present: true,
                    time_window_not_after: None,
                });
            }
            let basis_ref = body.get("basisRef")?.as_str()?;
            Some(ActBasisLink {
                basis_ref,
                ground_id: body.get("groundId").and_then(Value::as_str),
                power: body
                    .get("power")
                    .and_then(Value::as_str)
                    .unwrap_or("disclose"),
                targets: Vec::new(),
                is_retention_hold: false,
                review_at_present: true,
                time_window_not_after: None,
            })
        }
        KIND_RETENTION_HOLD => {
            let basis_ref = body.get("basisRef")?.as_str()?;
            let review_at_present = body
                .get("reviewAt")
                .and_then(Value::as_str)
                .is_some_and(is_valid_utc_z_datetime);
            let targets = body
                .get("targets")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            Some(ActBasisLink {
                basis_ref,
                ground_id: None,
                power: "hold",
                targets,
                is_retention_hold: true,
                review_at_present,
                time_window_not_after: None,
            })
        }
        _ => None,
    }
}

fn eval_v2_basis_declared_power(
    ctx: &A11EvalContext<'_>,
    valid_basis_refs: &BTreeSet<String>,
    findings: &mut Vec<A11Finding>,
) {
    for (idx, rec) in ctx.opened_records.iter().enumerate() {
        if ctx.body_result_by_idx.get(idx).map(String::as_str) != Some("ok") {
            continue;
        }
        let Some(link) = resolve_act_basis_link(ctx, rec) else {
            continue;
        };
        let basis_ref = link.basis_ref;
        let Some(&target_idx) = ctx.opened_by_ref.get(basis_ref) else {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "basis_declared_power",
                "incomplete",
                "basis_ref_missing",
                FindingCategory::UnavailableEvidence,
                Some(basis_ref.to_string()),
            ));
            continue;
        };
        let target_rec = &ctx.opened_records[target_idx];
        let target_kp = target_rec.kind_path();

        if target_kp.as_deref() == Some(KIND_BASIS_OVERLAY) {
            let otype = target_rec
                .payload
                .get("body")
                .and_then(|b| b.get("overlayType"))
                .and_then(Value::as_str);
            if otype == Some("amendment_proposal") {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "proposal_authorises_nothing",
                    FindingCategory::MechanicalCheck,
                    Some(basis_ref.to_string()),
                ));
            } else {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "basis_ref_wrong_kind",
                    FindingCategory::MechanicalCheck,
                    Some(basis_ref.to_string()),
                ));
            }
            continue;
        }

        if target_kp.as_deref() != Some(KIND_BASIS) {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "basis_declared_power",
                "failed",
                "basis_ref_wrong_kind",
                FindingCategory::MechanicalCheck,
                Some(basis_ref.to_string()),
            ));
            continue;
        }

        if !valid_basis_refs.contains(basis_ref) {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "basis_declared_power",
                "failed",
                "basis_invalid",
                FindingCategory::MechanicalCheck,
                Some(basis_ref.to_string()),
            ));
            continue;
        }

        let Some(basis_body) = target_rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };

        if link.is_retention_hold {
            if !link.review_at_present {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "retention_hold_missing_review_at",
                    FindingCategory::MechanicalCheck,
                    Some(basis_ref.to_string()),
                ));
                continue;
            }
            let has_hold_power = basis_body
                .get("grounds")
                .and_then(Value::as_array)
                .is_some_and(|grounds| {
                    grounds.iter().any(|g| {
                        g.get("powers").and_then(Value::as_array).is_some_and(|ps| {
                            ps.iter()
                                .any(|p| p.get("power").and_then(Value::as_str) == Some("hold"))
                        })
                    })
                });
            if !has_hold_power {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "act_cites_declared_or_absent_power",
                    FindingCategory::MechanicalCheck,
                    Some("hold".to_string()),
                ));
                continue;
            }
        } else if let Some(ground_id) = link.ground_id {
            let cites_declared_term = basis_body
                .get("declaredTerms")
                .and_then(Value::as_array)
                .is_some_and(|terms| {
                    terms
                        .iter()
                        .any(|t| t.get("termId").and_then(Value::as_str) == Some(ground_id))
                });
            if cites_declared_term {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "act_cites_declared_or_absent_power",
                    FindingCategory::MechanicalCheck,
                    Some(ground_id.to_string()),
                ));
                continue;
            }

            let matching_ground = basis_body
                .get("grounds")
                .and_then(Value::as_array)
                .and_then(|grounds| {
                    grounds
                        .iter()
                        .find(|g| g.get("groundId").and_then(Value::as_str) == Some(ground_id))
                });
            let Some(ground) = matching_ground else {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "act_cites_declared_or_absent_power",
                    FindingCategory::MechanicalCheck,
                    Some(ground_id.to_string()),
                ));
                continue;
            };

            let has_power = ground
                .get("powers")
                .and_then(Value::as_array)
                .is_some_and(|powers| {
                    powers
                        .iter()
                        .any(|p| p.get("power").and_then(Value::as_str) == Some(link.power))
                });
            if !has_power {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "act_cites_declared_or_absent_power",
                    FindingCategory::MechanicalCheck,
                    Some(link.power.to_string()),
                ));
                continue;
            }
        }

        // Check that every subject of every targeted session/record is covered by Basis.subjects.
        if !link.targets.is_empty() {
            let basis_subjects: BTreeSet<String> = basis_body
                .get("subjects")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let (target_subjects, _) = resolve_targets_subjects(ctx, &link.targets);
            if let Some(uncovered) = target_subjects.difference(&basis_subjects).next() {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "basis_subjects_do_not_cover_targets",
                    FindingCategory::MechanicalCheck,
                    Some(uncovered.clone()),
                ));
                continue;
            }
        }

        findings.push(A11Finding::new(
            3,
            &rec.rec_ref,
            "basis_declared_power",
            "ok",
            "ok",
            FindingCategory::MechanicalCheck,
            Some(basis_ref.to_string()),
        ));
    }
}

fn overlay_signer_authorized(
    ov: &OpenedRecord,
    basis_rec: &OpenedRecord,
    endorsements: &EndorsementIndex<'_>,
    authority_ok_by_idx: &[bool],
) -> bool {
    if !ov.all_sigs_ok || ov.signers.is_empty() {
        return false;
    }
    let Some(basis_body) = basis_rec.payload.get("body").and_then(Value::as_object) else {
        return false;
    };
    let mut allowed_identities: BTreeSet<&str> = BTreeSet::new();
    if let Some(inst) = basis_body.get("institution").and_then(Value::as_str) {
        allowed_identities.insert(inst);
    }
    if let Some(rep) = basis_body
        .get("representative")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        allowed_identities.insert(rep);
    }
    if let Some(subjs) = basis_body.get("subjects").and_then(Value::as_array) {
        for s in subjs {
            if let Some(ss) = s.as_str()
                && !ss.is_empty()
            {
                allowed_identities.insert(ss);
            }
        }
    }
    let ov_time = ov
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false));
    ov.signers.iter().any(|sk| {
        if basis_rec.signers.contains(sk) {
            return true;
        }
        endorsements
            .active_endorsements_at(sk, ov_time.as_ref(), Some(authority_ok_by_idx))
            .into_iter()
            .any(|e| {
                e.payload
                    .get("body")
                    .and_then(|b| b.get("actsFor"))
                    .and_then(Value::as_str)
                    .is_some_and(|af| allowed_identities.contains(af))
            })
    })
}

fn eval_v3_basis_overlay_order(
    ctx: &A11EvalContext<'_>,
    endorsements: &EndorsementIndex<'_>,
    overlays_by_basis: &BTreeMap<String, Vec<&OpenedRecord>>,
    witness_log_index_by_ref: &BTreeMap<String, i64>,
    findings: &mut Vec<A11Finding>,
) {
    // Index SessionClosed records by session URI for duration.untilEvent evaluation.
    let mut session_closed_by_session: BTreeMap<&str, Vec<&OpenedRecord>> = BTreeMap::new();
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_SESSION_CLOSED) {
            let sess = rec
                .payload
                .get("body")
                .and_then(|b| b.get("session"))
                .and_then(Value::as_str)
                .or_else(|| rec.payload.get("session").and_then(Value::as_str));
            if let Some(s) = sess {
                session_closed_by_session.entry(s).or_default().push(rec);
            }
        }
    }

    for (idx, rec) in ctx.opened_records.iter().enumerate() {
        if ctx.body_result_by_idx.get(idx).map(String::as_str) != Some("ok") {
            continue;
        }
        let Some(link) = resolve_act_basis_link(ctx, rec) else {
            continue;
        };
        let basis_ref = link.basis_ref;
        let Some(&basis_idx) = ctx.opened_by_ref.get(basis_ref) else {
            continue;
        };
        let basis_rec = &ctx.opened_records[basis_idx];
        if basis_rec.kind_path().as_deref() != Some(KIND_BASIS) {
            continue;
        }
        let Some(act_time) = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
        else {
            continue;
        };
        let act_stream = rec.payload.get("stream").and_then(Value::as_str);
        let act_seq = rec.payload.get("seq").and_then(parse_v2_integer);
        let act_witness_idx = witness_log_index_by_ref.get(&rec.rec_ref).copied();

        // Check withdrawal overlays in canonical order.
        if let Some(overlays) = overlays_by_basis.get(basis_ref) {
            let mut unauthorized_ov: Option<&OpenedRecord> = None;
            let mut active_withdrawal: Option<&OpenedRecord> = None;

            for &ov in overlays {
                let ov_body = ov.payload.get("body");
                let is_wd = ov_body
                    .and_then(|b| b.get("overlayType"))
                    .and_then(Value::as_str)
                    == Some("withdrawal");
                if !is_wd {
                    continue;
                }
                if !overlay_signer_authorized(ov, basis_rec, endorsements, ctx.authority_ok_by_idx)
                {
                    if unauthorized_ov.is_none() {
                        unauthorized_ov = Some(ov);
                    }
                    continue;
                }

                // Determine precedence:
                // - L2: when both overlay and act carry verified witness logIndex, compare logIndex.
                // - L1 same-stream: compare stream seq (prevents backdated effectiveAt / backdated act).
                // - L1 cross-stream: compare effectiveAt <= act_time.
                let ov_witness_idx = witness_log_index_by_ref.get(&ov.rec_ref).copied();
                let precedes = if let (Some(owi), Some(awi)) = (ov_witness_idx, act_witness_idx) {
                    owi < awi
                } else {
                    let ov_stream = ov.payload.get("stream").and_then(Value::as_str);
                    let ov_seq = ov.payload.get("seq").and_then(parse_v2_integer);
                    if let (Some(os), Some(as_), Some(oseq), Some(aseq)) =
                        (ov_stream, act_stream, ov_seq, act_seq)
                        && os == as_
                    {
                        oseq < aseq
                    } else {
                        let eff = ov_body
                            .and_then(|b| b.get("effectiveAt"))
                            .and_then(Value::as_str)
                            .and_then(|s| parse_rfc3339_instant(s, None, false));
                        eff.is_some_and(|t| t <= act_time)
                    }
                };

                if precedes {
                    active_withdrawal = Some(ov);
                    break;
                }
            }

            if let Some(wd) = active_withdrawal {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_overlay_order",
                    "failed",
                    "basis_power_withdrawn_or_expired",
                    FindingCategory::MechanicalCheck,
                    Some(wd.rec_ref.clone()),
                ));
                continue;
            }
            if let Some(unauth) = unauthorized_ov {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_overlay_order",
                    "failed",
                    "overlay_signer_unauthorized",
                    FindingCategory::MechanicalCheck,
                    Some(unauth.rec_ref.clone()),
                ));
                continue;
            }
        }

        // Check duration (until / untilEvent) on the cited ground/power.
        let power_obj = basis_rec
            .payload
            .get("body")
            .and_then(|b| b.get("grounds"))
            .and_then(Value::as_array)
            .and_then(|gs| {
                if let Some(gid) = link.ground_id {
                    gs.iter()
                        .find(|g| g.get("groundId").and_then(Value::as_str) == Some(gid))
                        .and_then(|g| g.get("powers"))
                        .and_then(Value::as_array)
                        .and_then(|ps| {
                            ps.iter().find(|p| {
                                p.get("power").and_then(Value::as_str) == Some(link.power)
                            })
                        })
                } else {
                    gs.iter().find_map(|g| {
                        g.get("powers").and_then(Value::as_array).and_then(|ps| {
                            ps.iter().find(|p| {
                                p.get("power").and_then(Value::as_str) == Some(link.power)
                            })
                        })
                    })
                }
            });

        if let Some(dur) = power_obj.and_then(|p| p.get("duration")) {
            if let Some(until_str) = dur.get("until").and_then(Value::as_str)
                && let Some(until_time) = parse_rfc3339_instant(until_str, None, false)
            {
                let expired = act_time > until_time
                    || link.time_window_not_after.is_some_and(|na| na > until_time);
                if expired {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "basis_overlay_order",
                        "failed",
                        "basis_power_withdrawn_or_expired",
                        FindingCategory::MechanicalCheck,
                        Some(basis_ref.to_string()),
                    ));
                    continue;
                }
            }
            if let Some(until_event) = dur.get("untilEvent").and_then(Value::as_str) {
                let mut trigger_ref: Option<String> = None;
                if until_event == "session_closed" {
                    // Check SessionClosed for any targeted session or act's own session.
                    let mut candidate_sessions: BTreeSet<&str> = BTreeSet::new();
                    for &t in &link.targets {
                        if t.starts_with("urn:r5e:session:") {
                            candidate_sessions.insert(t);
                        }
                    }
                    if let Some(s) = rec.payload.get("session").and_then(Value::as_str) {
                        candidate_sessions.insert(s);
                    }
                    for s in candidate_sessions {
                        if let Some(closed_recs) = session_closed_by_session.get(s) {
                            for &cr in closed_recs {
                                let cr_time = cr
                                    .payload
                                    .get("capturedAt")
                                    .and_then(Value::as_str)
                                    .and_then(|ts| parse_rfc3339_instant(ts, None, false));
                                let precedes = cr_time.is_some_and(|ct| ct <= act_time);
                                if precedes {
                                    trigger_ref = Some(cr.rec_ref.clone());
                                    break;
                                }
                            }
                        }
                        if trigger_ref.is_some() {
                            break;
                        }
                    }
                }

                if let Some(tref) = trigger_ref {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "basis_overlay_order",
                        "failed",
                        "basis_power_withdrawn_or_expired",
                        FindingCategory::MechanicalCheck,
                        Some(tref),
                    ));
                    continue;
                } else {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "basis_overlay_order",
                        "incomplete",
                        "until_event_unverified",
                        FindingCategory::UnavailableEvidence,
                        Some(until_event.to_string()),
                    ));
                    continue;
                }
            }
        }

        findings.push(A11Finding::new(
            3,
            &rec.rec_ref,
            "basis_overlay_order",
            "ok",
            "ok",
            FindingCategory::MechanicalCheck,
            Some(basis_ref.to_string()),
        ));
    }
}

fn verify_hardware_attestation(
    endorsement: &OpenedRecord,
    signer_key: &str,
    contract: &DeploymentContract,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
    salted_cache: &BTreeMap<String, Result<Vec<u8>, ()>>,
    available_keys: &BTreeMap<String, AvailableKey>,
) -> bool {
    let Some(att_ref) = endorsement
        .payload
        .get("body")
        .and_then(|b| b.get("hardwareAttestationRef"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(raw) = load_carried_content(att_ref, valid_blobs, salted_cache) else {
        return false;
    };
    let Some(att_val) = parse_canonical_json(raw) else {
        return false;
    };
    let Some(aobj) = att_val.as_object() else {
        return false;
    };
    if aobj.len() != 5 {
        return false;
    }
    let (Some(attested_at), Some(device), Some(key_id), Some(root_key_id), Some(sig_b64)) = (
        aobj.get("attestedAt").and_then(Value::as_str),
        aobj.get("device").and_then(Value::as_str),
        aobj.get("keyId").and_then(Value::as_str),
        aobj.get("rootKeyId").and_then(Value::as_str),
        aobj.get("signature").and_then(Value::as_str),
    ) else {
        return false;
    };
    if device.is_empty() || !is_valid_utc_z_datetime(attested_at) {
        return false;
    }
    if !ct_eq_str(key_id, signer_key) {
        return false;
    }
    let allowed_roots = if !contract.hardware_attestation_roots.is_empty() {
        &contract.hardware_attestation_roots
    } else {
        &contract.deployment_roots
    };
    if !allowed_roots.contains(root_key_id) {
        return false;
    }
    let unsigned = json!({
        "attestedAt": attested_at,
        "device": device,
        "keyId": key_id,
        "rootKeyId": root_key_id,
    });
    verify_embedded_signature(
        root_key_id,
        sig_b64,
        DOMAIN_HW_ATTESTATION,
        &unsigned,
        available_keys,
    )
}

fn eval_v4_release_request_approvals(
    ctx: &A11EvalContext<'_>,
    history: &ContractHistory,
    endorsements: &EndorsementIndex<'_>,
    salted_cache: &BTreeMap<String, Result<Vec<u8>, ()>>,
    valid_basis_refs: &BTreeSet<String>,
    findings: &mut Vec<A11Finding>,
) {
    for (idx, rec) in ctx.opened_records.iter().enumerate() {
        if rec.kind_path().as_deref() != Some(KIND_RELEASE_REQUEST) {
            continue;
        }
        if ctx.body_result_by_idx.get(idx).map(String::as_str) != Some("ok") {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let (Some(request_id), Some(basis_ref), Some(contract_version), Some(recipient_key)) = (
            body.get("requestId").and_then(Value::as_str),
            body.get("basisRef").and_then(Value::as_str),
            body.get("contractVersion").and_then(Value::as_str),
            body.get("recipientKey").and_then(Value::as_str),
        ) else {
            continue;
        };

        // Require a valid resolved Basis (never emit ok if basisRef is missing/wrong-kind/invalid).
        let Some(&basis_idx) = ctx.opened_by_ref.get(basis_ref) else {
            continue;
        };
        let brec = &ctx.opened_records[basis_idx];
        if brec.kind_path().as_deref() != Some(KIND_BASIS) || !valid_basis_refs.contains(basis_ref)
        {
            continue;
        }

        let act_time = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false));
        let contract = history.resolve(Some(contract_version), act_time.as_ref());

        // 1. Check ReleaseRequest.targets resolution and ReleaseRequest.subjects completeness.
        let targets: Vec<&str> = body
            .get("targets")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let (target_subjects, missing_targets) = resolve_targets_subjects(ctx, &targets);

        let basis_subjects: BTreeSet<String> = brec
            .payload
            .get("body")
            .and_then(|b| b.get("subjects"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let mut expected_subjects: BTreeSet<String> = basis_subjects;
        expected_subjects.extend(target_subjects);

        let req_subjects: BTreeSet<String> = body
            .get("subjects")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        if let Some(missing_subj) = expected_subjects.difference(&req_subjects).next() {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "failed",
                "release_subjects_incomplete",
                FindingCategory::MechanicalCheck,
                Some(missing_subj.clone()),
            ));
            continue;
        }
        if let Some(extra_subj) = req_subjects.difference(&expected_subjects).next() {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "failed",
                "release_subjects_incomplete",
                FindingCategory::MechanicalCheck,
                Some(extra_subj.clone()),
            ));
            continue;
        }

        if let Some(first_missing_target) = missing_targets.first() {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "incomplete",
                "release_target_missing",
                FindingCategory::UnavailableEvidence,
                Some(first_missing_target.clone()),
            ));
            continue;
        }

        // 2. Verify every approval signature, active endorsement, hardware keyStorage, and role pinning.
        let Some(approvals) = body.get("approvals").and_then(Value::as_array) else {
            continue;
        };
        if approvals.len() > MAX_APPROVALS {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "failed",
                "approval_signature_invalid",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        }

        let approval_msg = json!({
            "basisFingerprint": basis_ref,
            "contractVersion": contract_version,
            "recipientKey": recipient_key,
            "requestId": request_id,
        });

        let mut failed = false;
        let mut unverified_hw_signer: Option<String> = None;
        let mut valid_signers_by_role: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut seen_signer_roles: BTreeSet<(String, String)> = BTreeSet::new();
        let mut first_valid_signer: Option<String> = None;

        for app in approvals {
            let (Some(signer_key), Some(role), Some(sig_b64)) = (
                app.get("signerKey").and_then(Value::as_str),
                app.get("role").and_then(Value::as_str),
                app.get("signature").and_then(Value::as_str),
            ) else {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "approval_signature_invalid",
                    FindingCategory::CryptographicProof,
                    None,
                ));
                failed = true;
                break;
            };

            if !seen_signer_roles.insert((signer_key.to_string(), role.to_string())) {
                continue;
            }

            if !verify_embedded_signature(
                signer_key,
                sig_b64,
                DOMAIN_RELEASE_APPROVAL,
                &approval_msg,
                ctx.available_keys,
            ) {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "approval_signature_invalid",
                    FindingCategory::CryptographicProof,
                    Some(signer_key.to_string()),
                ));
                failed = true;
                break;
            }

            // Look up latest active (valid, non-revoked, in-window) Endorsement for signer_key.
            let Some(matching_endorsement) = endorsements.latest_active_at(
                signer_key,
                act_time.as_ref(),
                Some(ctx.authority_ok_by_idx),
            ) else {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "approval_endorsement_inactive",
                    FindingCategory::MechanicalCheck,
                    Some(signer_key.to_string()),
                ));
                failed = true;
                break;
            };

            let key_storage = matching_endorsement
                .payload
                .get("body")
                .and_then(|b| b.get("keyStorage"))
                .and_then(Value::as_str);
            if key_storage != Some("hardware") {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "approval_key_not_hardware",
                    FindingCategory::MechanicalCheck,
                    Some(signer_key.to_string()),
                ));
                failed = true;
                break;
            }

            // Fail closed if contract approverRoles omits role or does not list signer_key.
            let role_allowed = contract
                .approver_roles
                .get(role)
                .is_some_and(|keys| keys.contains(signer_key));
            if !role_allowed {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "approval_role_unlisted",
                    FindingCategory::MechanicalCheck,
                    Some(role.to_string()),
                ));
                failed = true;
                break;
            }

            if !verify_hardware_attestation(
                matching_endorsement,
                signer_key,
                contract,
                ctx.valid_blobs,
                salted_cache,
                ctx.available_keys,
            ) && unverified_hw_signer.is_none()
            {
                unverified_hw_signer = Some(signer_key.to_string());
            }

            valid_signers_by_role
                .entry(role.to_string())
                .or_default()
                .insert(signer_key.to_string());
            if first_valid_signer.is_none() {
                first_valid_signer = Some(signer_key.to_string());
            }
        }

        if failed {
            continue;
        }

        // 3. Check approvalRule threshold using i64 directly (never truncating to usize).
        if let Some(ground_id) = body.get("groundId").and_then(Value::as_str) {
            let power = body
                .get("power")
                .and_then(Value::as_str)
                .unwrap_or("disclose");
            let approval_rule = brec
                .payload
                .get("body")
                .and_then(|b| b.get("grounds"))
                .and_then(Value::as_array)
                .and_then(|gs| {
                    gs.iter()
                        .find(|g| g.get("groundId").and_then(Value::as_str) == Some(ground_id))
                })
                .and_then(|g| g.get("powers"))
                .and_then(Value::as_array)
                .and_then(|ps| {
                    ps.iter()
                        .find(|p| p.get("power").and_then(Value::as_str) == Some(power))
                })
                .and_then(|p| p.get("approvalRule"));

            if let Some(rule) = approval_rule {
                let threshold = rule
                    .get("threshold")
                    .and_then(parse_v2_integer)
                    .unwrap_or(1)
                    .max(1);
                let allowed_roles: BTreeSet<&str> = rule
                    .get("roles")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mut distinct_qualifying: BTreeSet<&str> = BTreeSet::new();
                for (r, signers) in &valid_signers_by_role {
                    if allowed_roles.contains(r.as_str()) {
                        for s in signers {
                            distinct_qualifying.insert(s.as_str());
                        }
                    }
                }
                if (distinct_qualifying.len() as i64) < threshold {
                    findings.push(A11Finding::new(
                        2,
                        &rec.rec_ref,
                        "release_request_approvals",
                        "failed",
                        "approval_threshold_not_met",
                        FindingCategory::MechanicalCheck,
                        Some(basis_ref.to_string()),
                    ));
                    continue;
                }
            }
        }

        if let Some(unverified_signer) = unverified_hw_signer {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "incomplete",
                "hardware_attestation_unverified",
                FindingCategory::InstitutionalAssertion,
                Some(unverified_signer),
            ));
        } else {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_request_approvals",
                "ok",
                "ok",
                FindingCategory::CryptographicProof,
                first_valid_signer,
            ));
        }
    }
}

fn verify_single_witness_receipt(
    ctx: &A11EvalContext<'_>,
    history: &ContractHistory,
    subject: &str,
    w_ref: &str,
    receipt: &Value,
    expected_req_ref: Option<&str>,
    findings: &mut Vec<A11Finding>,
) -> Option<(String, i64)> {
    // 1. Check map key == bytes:sha256:sha256(canonical_json(receipt)) in constant time.
    let key_matches = encode_canonical_json(receipt)
        .is_some_and(|c| ct_eq_str(&bytes_ref_of(c.as_bytes()), w_ref));
    if !key_matches {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_receipt_hash_mismatch",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
        return None;
    }

    let (
        Some(log_index),
        Some(logged_at),
        Some(req_hash),
        Some(rcpt_req_ref),
        Some(sig_b64),
        Some(witness_key),
    ) = (
        receipt.get("logIndex").and_then(parse_v2_integer),
        receipt.get("loggedAt").and_then(Value::as_str),
        receipt.get("requestHash").and_then(Value::as_str),
        receipt.get("requestRef").and_then(Value::as_str),
        receipt.get("signature").and_then(Value::as_str),
        receipt.get("witnessKey").and_then(Value::as_str),
    )
    else {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_receipt_hash_mismatch",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
        return None;
    };

    // Resolve contract for witness key pinning.
    let logged_time = parse_rfc3339_instant(logged_at, None, false);
    let contract_version = ctx.opened_by_ref.get(rcpt_req_ref).and_then(|&idx| {
        ctx.opened_records[idx]
            .payload
            .get("body")
            .and_then(|b| b.get("contractVersion"))
            .and_then(Value::as_str)
    });
    let contract = history.resolve(contract_version, logged_time.as_ref());

    // 2. Check pinned witnessKey.
    if !contract.witness_keys.contains(witness_key) {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_unpinned",
            FindingCategory::CryptographicProof,
            Some(witness_key.to_string()),
        ));
        return None;
    }

    // 3. Verify signature with constant-time key-ID binding.
    let unsigned = json!({
        "logIndex": log_index,
        "loggedAt": logged_at,
        "requestHash": req_hash,
        "requestRef": rcpt_req_ref,
        "witnessKey": witness_key,
    });
    if !verify_embedded_signature(
        witness_key,
        sig_b64,
        DOMAIN_WITNESS_RECEIPT,
        &unsigned,
        ctx.available_keys,
    ) {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_receipt_hash_mismatch",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
        return None;
    }

    // 4. Resolve requestRef in bundle.records.
    if let Some(exp_rr) = expected_req_ref
        && rcpt_req_ref != exp_rr
    {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_receipt_hash_mismatch",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
        return None;
    }

    let Some(&req_idx) = ctx.opened_by_ref.get(rcpt_req_ref) else {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "incomplete",
            "witness_request_missing",
            FindingCategory::UnavailableEvidence,
            Some(rcpt_req_ref.to_string()),
        ));
        return None;
    };
    let req_rec = &ctx.opened_records[req_idx];
    if !matches!(
        req_rec.kind_path().as_deref(),
        Some(KIND_RELEASE_REQUEST | KIND_BASIS_OVERLAY)
    ) {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_request_wrong_kind",
            FindingCategory::CryptographicProof,
            Some(rcpt_req_ref.to_string()),
        ));
        return None;
    }

    // 5. Verify requestHash == "sha256:" || hex(sha256(request_payload_bytes)) in constant time.
    let expected_hash = req_rec
        .rec_ref
        .strip_prefix("evidence:sha256:")
        .map(|h| format!("sha256:{h}"));
    if !expected_hash
        .as_deref()
        .is_some_and(|eh| ct_eq_str(eh, req_hash))
    {
        findings.push(A11Finding::new(
            3,
            subject,
            "witness_receipt_binding",
            "failed",
            "witness_receipt_hash_mismatch",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
        return None;
    }

    findings.push(A11Finding::new(
        3,
        subject,
        "witness_receipt_binding",
        "ok",
        "ok",
        FindingCategory::CryptographicProof,
        Some(w_ref.to_string()),
    ));
    Some((rcpt_req_ref.to_string(), log_index))
}

fn eval_v5_witness_receipt_binding(
    ctx: &A11EvalContext<'_>,
    history: &ContractHistory,
    findings: &mut Vec<A11Finding>,
) -> BTreeMap<String, i64> {
    let mut witness_log_index_by_ref: BTreeMap<String, i64> = BTreeMap::new();
    let witness_receipts = ctx.bundle.get("witnessReceipts").and_then(Value::as_object);
    let mut referenced_w_refs: BTreeSet<String> = BTreeSet::new();

    // Reject any ReleaseRequest embedding witnessReceiptRef.
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_RELEASE_REQUEST)
            && rec
                .payload
                .get("body")
                .and_then(|b| b.get("witnessReceiptRef"))
                .is_some()
        {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "witness_receipt_binding",
                "failed",
                "witness_receipt_hash_mismatch",
                FindingCategory::CryptographicProof,
                None,
            ));
        }
    }

    // Validate witness receipts referenced by ReleaseReceipt records.
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_RELEASE_RECEIPT) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let Some(w_ref) = body.get("witnessReceiptRef").and_then(Value::as_str) else {
            continue;
        };
        let Some(req_ref) = body.get("requestRef").and_then(Value::as_str) else {
            continue;
        };
        referenced_w_refs.insert(w_ref.to_string());

        let Some(receipt) = witness_receipts.and_then(|m| m.get(w_ref)) else {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "witness_receipt_binding",
                "failed",
                "witness_receipt_hash_mismatch",
                FindingCategory::CryptographicProof,
                Some(w_ref.to_string()),
            ));
            continue;
        };

        if let Some((target_ref, log_idx)) = verify_single_witness_receipt(
            ctx,
            history,
            &rec.rec_ref,
            w_ref,
            receipt,
            Some(req_ref),
            findings,
        ) {
            witness_log_index_by_ref.insert(target_ref, log_idx);
        }
    }

    // Validate all remaining standalone witnessReceipts entries (including BasisOverlay receipts).
    if let Some(wmap) = witness_receipts {
        for (w_ref, receipt) in wmap {
            if referenced_w_refs.contains(w_ref) {
                continue;
            }
            if let Some((target_ref, log_idx)) =
                verify_single_witness_receipt(ctx, history, w_ref, w_ref, receipt, None, findings)
            {
                witness_log_index_by_ref.insert(target_ref, log_idx);
            }
        }
    }

    witness_log_index_by_ref
}

fn eval_v6_release_receipt_fingerprint(
    ctx: &A11EvalContext<'_>,
    history: &ContractHistory,
    findings: &mut Vec<A11Finding>,
) {
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_RELEASE_RECEIPT) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let Some(outcome) = body.get("outcome").and_then(Value::as_str) else {
            continue;
        };
        let fp = body.get("releasedFingerprint").and_then(Value::as_str);
        let w_ref = body.get("witnessReceiptRef").and_then(Value::as_str);

        // Resolve contract at the linked ReleaseRequest's contractVersion (or receipt capture time).
        let req_contract_version = body
            .get("requestRef")
            .and_then(Value::as_str)
            .and_then(|rr| ctx.opened_by_ref.get(rr))
            .and_then(|&idx| {
                ctx.opened_records[idx]
                    .payload
                    .get("body")
                    .and_then(|b| b.get("contractVersion"))
                    .and_then(Value::as_str)
            });
        let rcpt_time = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false));
        let contract = history.resolve(req_contract_version, rcpt_time.as_ref());

        let mut any_failed = false;

        // Check 1: releasedFingerprint presence iff outcome in {"released", "delivered"}.
        let expects_fp = matches!(outcome, "released" | "delivered");
        if expects_fp {
            if fp.is_none() {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_receipt_fingerprint",
                    "failed",
                    "released_fingerprint_missing",
                    FindingCategory::MechanicalCheck,
                    None,
                ));
                any_failed = true;
            }
        } else if let Some(fp_str) = fp {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_receipt_fingerprint",
                "failed",
                "released_fingerprint_unexpected",
                FindingCategory::MechanicalCheck,
                Some(fp_str.to_string()),
            ));
            any_failed = true;
        }

        // Check 2: Level 2 requires witnessReceiptRef (evaluated independently without short-circuiting).
        if contract.custody_level == Some(2) && w_ref.is_none() {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_receipt_fingerprint",
                "failed",
                "witness_receipt_missing_l2",
                FindingCategory::MechanicalCheck,
                None,
            ));
            any_failed = true;
        }

        if !any_failed {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_receipt_fingerprint",
                "ok",
                "ok",
                FindingCategory::MechanicalCheck,
                fp.map(str::to_string),
            ));
        }
    }
}

fn eval_v7_succession_recovery_inner(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    available_keys: &BTreeMap<String, AvailableKey>,
    base_defs: &BaseDefinitions,
    history: &ContractHistory,
    endorsements: &EndorsementIndex<'_>,
    findings: &mut Vec<A11Finding>,
) -> BTreeSet<String> {
    let mut verified_recovery_refs: BTreeSet<String> = BTreeSet::new();

    // Excluded institutional keys: deployment roots, endorsement issuer keys, and approver-role keys.
    let mut excluded_institutional: BTreeSet<&str> = BTreeSet::new();
    for k in &history.all_deployment_roots {
        excluded_institutional.insert(k.as_str());
    }
    for k in &history.all_approver_keys {
        excluded_institutional.insert(k.as_str());
    }
    for k in &endorsements.all_issuer_keys {
        excluded_institutional.insert(k.as_str());
    }

    // Track active recoveryRule ref per key:
    // Start with the earliest valid Endorsement carrying a recoveryRule for each key.
    let mut active_rule_ref_by_key: BTreeMap<String, String> = BTreeMap::new();
    for (subj, list) in &endorsements.by_subject {
        if let Some((_, first_with_rule)) = list.iter().find(|(_, e)| {
            e.payload
                .get("body")
                .and_then(|b| b.get("recoveryRule"))
                .is_some_and(Value::is_object)
        }) {
            active_rule_ref_by_key.insert(subj.clone(), first_with_rule.rec_ref.clone());
        }
    }

    // Process Succession records in deterministic (capturedAt, seq, ref) order so a prior
    // valid Succession carrying `recoveryRule` updates the active rule for its successor.
    let mut succ_recs: Vec<&OpenedRecord> = opened_records
        .iter()
        .filter(|r| r.kind_path().as_deref() == Some(KIND_SUCCESSION))
        .collect();
    succ_recs.sort_by(|a, b| record_sort_key(a).cmp(&record_sort_key(b)));

    for rec in succ_recs {
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let (Some(predecessor), Some(successor)) = (
            body.get("predecessor").and_then(Value::as_str),
            body.get("successor").and_then(Value::as_str),
        ) else {
            continue;
        };

        // Skip frozen baseline Succession records that have no recoveryProof / recoveryRule.
        let is_frozen_baseline = rec
            .payload
            .get("schemaRef")
            .and_then(Value::as_str)
            .is_some_and(|sr| base_defs.contains_index_ref(sr));
        if is_frozen_baseline
            && body.get("recoveryProof").is_none()
            && body.get("recoveryRule").is_none()
        {
            continue;
        }

        let Some(rp) = body.get("recoveryProof").and_then(Value::as_object) else {
            // Standard dual-key succession form: signers must be [predecessor, successor] in order.
            let std_ok = rec.all_sigs_ok
                && rec.signers.len() == 2
                && rec.signers[0] == predecessor
                && rec.signers[1] == successor;
            if std_ok {
                if body.get("recoveryRule").is_some_and(Value::is_object) {
                    active_rule_ref_by_key.insert(successor.to_string(), rec.rec_ref.clone());
                }
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "succession_recovery",
                    "ok",
                    "ok",
                    FindingCategory::CryptographicProof,
                    None,
                ));
            } else {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "succession_recovery",
                    "failed",
                    "succession_signer_mismatch",
                    FindingCategory::CryptographicProof,
                    None,
                ));
            }
            continue;
        };

        // Recovery form: successor must be the sole valid envelope signer.
        let succ_sig_ok = rec.all_sigs_ok && rec.signers.len() == 1 && rec.signers[0] == successor;
        if !succ_sig_ok {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_signer_mismatch",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        }

        let (Some(rule_ref), Some(approvals)) = (
            rp.get("recoveryRuleRef").and_then(Value::as_str),
            rp.get("approvals").and_then(Value::as_array),
        ) else {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_recovery_rule_unknown",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        };

        // Verify rule_ref matches predecessor's active registered rule (earliest Endorsement or prior valid Succession).
        let rule_matches_active = active_rule_ref_by_key
            .get(predecessor)
            .is_some_and(|active| active == rule_ref);
        let rule_obj = if rule_matches_active {
            opened_by_ref
                .get(rule_ref)
                .map(|&idx| &opened_records[idx])
                .and_then(|r| r.payload.get("body"))
                .and_then(|b| b.get("recoveryRule"))
                .and_then(Value::as_object)
        } else {
            None
        };

        let Some(rule) = rule_obj else {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_recovery_rule_unknown",
                FindingCategory::CryptographicProof,
                Some(rule_ref.to_string()),
            ));
            continue;
        };

        if approvals.len() > MAX_APPROVALS {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_recovery_threshold_not_met",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        }

        let threshold = rule
            .get("threshold")
            .and_then(parse_v2_integer)
            .unwrap_or(1)
            .max(1);
        let allowed_keys: BTreeSet<&str> = rule
            .get("recoveryKeys")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        let recovery_msg = json!({
            "newKey": successor,
            "oldKey": predecessor,
            "recoveryRuleRef": rule_ref,
        });

        let mut valid_signers: BTreeSet<&str> = BTreeSet::new();
        for app in approvals {
            if let (Some(sk), Some(sig_b64)) = (
                app.get("signerKey").and_then(Value::as_str),
                app.get("signature").and_then(Value::as_str),
            ) && allowed_keys.contains(sk)
                && verify_embedded_signature(
                    sk,
                    sig_b64,
                    DOMAIN_SUCCESSION_RECOVERY,
                    &recovery_msg,
                    available_keys,
                )
            {
                valid_signers.insert(sk);
            }
        }

        // Compare using i64 directly (never truncating to usize).
        if (valid_signers.len() as i64) < threshold {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_recovery_threshold_not_met",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        }

        let has_non_institutional = valid_signers
            .iter()
            .any(|sk| !excluded_institutional.contains(sk));
        if !has_non_institutional {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "succession_recovery",
                "failed",
                "succession_institution_only_rejected",
                FindingCategory::CryptographicProof,
                None,
            ));
            continue;
        }

        verified_recovery_refs.insert(rec.rec_ref.clone());
        if body.get("recoveryRule").is_some_and(Value::is_object) {
            active_rule_ref_by_key.insert(successor.to_string(), rec.rec_ref.clone());
        }
        findings.push(A11Finding::new(
            2,
            &rec.rec_ref,
            "succession_recovery",
            "ok",
            "ok",
            FindingCategory::CryptographicProof,
            None,
        ));
    }

    verified_recovery_refs
}

fn eval_v8_erasure_l2_proof(
    ctx: &A11EvalContext<'_>,
    history: &ContractHistory,
    salted_cache: &BTreeMap<String, Result<Vec<u8>, ()>>,
    findings: &mut Vec<A11Finding>,
) {
    for (idx, rec) in ctx.opened_records.iter().enumerate() {
        if rec.kind_path().as_deref() != Some(KIND_ERASURE_ANSWER) {
            continue;
        }
        if ctx.body_result_by_idx.get(idx).map(String::as_str) != Some("ok") {
            continue;
        }
        let Some(sessions) = rec
            .payload
            .get("body")
            .and_then(|b| b.get("sessions"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        let act_time = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false));
        let contract = history.resolve(None, act_time.as_ref());

        for entry in sessions {
            let Some(session) = entry.get("session").and_then(Value::as_str) else {
                continue;
            };
            let Some(gov_state) = entry.get("governedState").and_then(Value::as_str) else {
                continue;
            };
            if gov_state != "destroyed" {
                continue;
            }
            let Some(ev_support) = entry.get("evidentialSupport").and_then(Value::as_str) else {
                continue;
            };

            if ev_support == "institution_claim" {
                if contract.custody_level == Some(2) {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_institution_claim_at_l2",
                        FindingCategory::CryptographicProof,
                        Some(session.to_string()),
                    ));
                } else {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "erasure_l2_proof",
                        "ok",
                        "ok",
                        FindingCategory::InstitutionalAssertion,
                        Some(session.to_string()),
                    ));
                }
                continue;
            }

            if ev_support != "sealed_key_service_proof" {
                continue;
            }

            // Contract sealedServiceCopies must be non-empty (no vacuous 0-copy pass).
            if contract.sealed_service_copies.is_empty() {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(session.to_string()),
                ));
                continue;
            }

            let confirmed: Vec<&str> = entry
                .get("confirmedCopies")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();

            // Emit one finding per unknown copyId not in contract.sealed_service_copies.
            let unknown_copies: Vec<&str> = confirmed
                .iter()
                .copied()
                .filter(|cid| !contract.sealed_service_copies.contains_key(*cid))
                .collect();
            if !unknown_copies.is_empty() {
                for unknown in unknown_copies {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_unknown_copy_id",
                        FindingCategory::CryptographicProof,
                        Some(unknown.to_string()),
                    ));
                }
                continue;
            }

            // Load and parse proofRef blob or verified salted content.
            let proof_val = entry
                .get("proofRef")
                .and_then(Value::as_str)
                .and_then(|pref| load_carried_content(pref, ctx.valid_blobs, salted_cache))
                .and_then(parse_canonical_json);
            let Some(proof) = proof_val else {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(session.to_string()),
                ));
                continue;
            };

            let (Some(destroyed_at), Some(proof_session), Some(confs)) = (
                proof.get("destroyedAt").and_then(Value::as_str),
                proof.get("session").and_then(Value::as_str),
                proof.get("copyConfirmations").and_then(Value::as_array),
            ) else {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(session.to_string()),
                ));
                continue;
            };

            if proof_session != session {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(session.to_string()),
                ));
                continue;
            }

            // Index copyConfirmations by copyId in O(K) and reject duplicates.
            let mut conf_by_copy: BTreeMap<&str, &Value> = BTreeMap::new();
            let mut duplicate_cid: Option<String> = None;
            for c in confs {
                if let Some(cid) = c.get("copyId").and_then(Value::as_str)
                    && conf_by_copy.insert(cid, c).is_some()
                {
                    duplicate_cid = Some(cid.to_string());
                    break;
                }
            }
            if let Some(dup) = duplicate_cid {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(dup),
                ));
                continue;
            }

            // Verify proof signature for every copy listed in confirmedCopies against its pinned keyId.
            let mut bad_copy: Option<String> = None;
            for &copy_id in &confirmed {
                let expected_key_id = contract.sealed_service_copies.get(copy_id);
                let matching_conf = conf_by_copy.get(copy_id).copied();
                let verified = match (expected_key_id, matching_conf) {
                    (Some(exp_kid), Some(c)) => {
                        if let (Some(kid), Some(sig_b64)) = (
                            c.get("keyId").and_then(Value::as_str),
                            c.get("signature").and_then(Value::as_str),
                        ) && ct_eq_str(kid, exp_kid)
                        {
                            let msg = json!({
                                "copyId": copy_id,
                                "destroyedAt": destroyed_at,
                                "session": session,
                            });
                            verify_embedded_signature(
                                kid,
                                sig_b64,
                                DOMAIN_ERASURE_PROOF,
                                &msg,
                                ctx.available_keys,
                            )
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if !verified {
                    bad_copy = Some(copy_id.to_string());
                    break;
                }
            }
            if let Some(cid) = bad_copy {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_proof_invalid_or_missing_l2",
                    FindingCategory::CryptographicProof,
                    Some(cid),
                ));
                continue;
            }

            // Emit one incomplete finding per pending contract copy.
            let confirmed_set: BTreeSet<&str> = confirmed.into_iter().collect();
            let pending_copies: Vec<&String> = contract
                .sealed_service_copies
                .keys()
                .filter(|c| !confirmed_set.contains(c.as_str()))
                .collect();
            if !pending_copies.is_empty() {
                for pending in pending_copies {
                    findings.push(A11Finding::new(
                        3,
                        &rec.rec_ref,
                        "erasure_l2_proof",
                        "incomplete",
                        "erasure_copy_confirmation_pending",
                        FindingCategory::UnavailableEvidence,
                        Some(pending.clone()),
                    ));
                }
            } else {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "ok",
                    "ok",
                    FindingCategory::CryptographicProof,
                    Some(session.to_string()),
                ));
            }
        }
    }
}

fn eval_v9_salted_content_ref(
    ctx: &A11EvalContext<'_>,
    salted_cache: &BTreeMap<String, Result<Vec<u8>, ()>>,
    findings: &mut Vec<A11Finding>,
) {
    let mut referenced_salted: BTreeSet<String> = BTreeSet::new();

    for rec in ctx.opened_records {
        let Some(body) = rec.payload.get("body") else {
            continue;
        };
        let mut refs = BTreeSet::new();
        collect_salted_refs(body, &mut refs);
        for s_ref in refs {
            referenced_salted.insert(s_ref.clone());
            match salted_cache.get(&s_ref) {
                None => {
                    findings.push(A11Finding::new(
                        1,
                        &rec.rec_ref,
                        "salted_content_ref",
                        "incomplete",
                        "salted_content_omitted",
                        FindingCategory::UnavailableEvidence,
                        Some(s_ref),
                    ));
                }
                Some(Ok(_)) => {
                    findings.push(A11Finding::new(
                        1,
                        &rec.rec_ref,
                        "salted_content_ref",
                        "ok",
                        "ok",
                        FindingCategory::CryptographicProof,
                        Some(s_ref),
                    ));
                }
                Some(Err(())) => {
                    findings.push(A11Finding::new(
                        1,
                        &rec.rec_ref,
                        "salted_content_ref",
                        "failed",
                        "salted_content_digest_mismatch",
                        FindingCategory::CryptographicProof,
                        Some(s_ref),
                    ));
                }
            }
        }
    }

    // Also fail any unreferenced carried saltedContent entry whose digest does not match.
    for (s_ref, res) in salted_cache {
        if !referenced_salted.contains(s_ref) && res.is_err() {
            findings.push(A11Finding::new(
                1,
                s_ref,
                "salted_content_ref",
                "failed",
                "salted_content_digest_mismatch",
                FindingCategory::CryptographicProof,
                Some(s_ref.clone()),
            ));
        }
    }
}

fn eval_v10_checkpoint_and_unlock_log(
    ctx: &A11EvalContext<'_>,
    salted_cache: &BTreeMap<String, Result<Vec<u8>, ()>>,
    findings: &mut Vec<A11Finding>,
) {
    // 10a. Checkpoints: combine reader-supplied trustedCheckpoints and bundle pinnedCheckpoints.
    let mut checkpoints_by_seq: BTreeMap<i64, Vec<&OpenedRecord>> = BTreeMap::new();
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_CHECKPOINT)
            && let Some(seq) = rec.payload.get("seq").and_then(parse_v2_integer)
        {
            checkpoints_by_seq.entry(seq).or_default().push(rec);
        }
    }

    let mut all_pins: BTreeSet<(i64, String)> = BTreeSet::new();
    for tc in ctx.trusted_checkpoints {
        all_pins.insert((tc.seq as i64, tc.rec_ref.clone()));
    }
    if let Some(pinned_arr) = ctx
        .bundle
        .get("pinnedCheckpoints")
        .and_then(Value::as_array)
    {
        for pin in pinned_arr {
            if let (Some(pinned_ref), Some(pinned_seq)) = (
                pin.get("ref").and_then(Value::as_str),
                pin.get("seq").and_then(parse_v2_integer),
            ) {
                all_pins.insert((pinned_seq, pinned_ref.to_string()));
            }
        }
    }

    for (pinned_seq, pinned_ref) in &all_pins {
        match checkpoints_by_seq.get(pinned_seq) {
            Some(ckpts) => {
                for ckpt in ckpts {
                    if !ct_eq_str(&ckpt.rec_ref, pinned_ref) {
                        findings.push(A11Finding::new(
                            3,
                            &ckpt.rec_ref,
                            "checkpoint_and_unlock_log",
                            "failed",
                            "checkpoint_fork_or_stale",
                            FindingCategory::CryptographicProof,
                            Some(pinned_ref.clone()),
                        ));
                    }
                }
            }
            None => {
                findings.push(A11Finding::new(
                    3,
                    "bundle",
                    "checkpoint_and_unlock_log",
                    "failed",
                    "checkpoint_fork_or_stale",
                    FindingCategory::CryptographicProof,
                    Some(pinned_ref.clone()),
                ));
            }
        }
    }

    // Check strictly monotonic checkpoint sequence order in bundle.checkpoints.
    if let Some(ckpt_refs) = ctx.bundle.get("checkpoints").and_then(Value::as_array) {
        let mut prev_seq: Option<i64> = None;
        for cv in ckpt_refs {
            if let Some(cref) = cv.as_str()
                && let Some(&idx) = ctx.opened_by_ref.get(cref)
                && let Some(seq) = ctx.opened_records[idx]
                    .payload
                    .get("seq")
                    .and_then(parse_v2_integer)
            {
                if let Some(pseq) = prev_seq
                    && seq <= pseq
                {
                    findings.push(A11Finding::new(
                        3,
                        cref,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "checkpoint_fork_or_stale",
                        FindingCategory::CryptographicProof,
                        Some(format!("seq:{seq}")),
                    ));
                }
                prev_seq = Some(seq);
            }
        }
    }

    // Collect valid release/disclosure records with per-record target coverage AND global coverage.
    let mut coverage_by_release: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut disclosed_targets: BTreeSet<String> = BTreeSet::new();

    for rec in ctx.opened_records {
        match rec.kind_path().as_deref() {
            Some(KIND_RELEASE_RECEIPT) => {
                let outcome = rec
                    .payload
                    .get("body")
                    .and_then(|b| b.get("outcome"))
                    .and_then(Value::as_str);
                if matches!(outcome, Some("released" | "delivered")) {
                    let mut cov = BTreeSet::new();
                    if let Some(req_ref) = rec
                        .payload
                        .get("body")
                        .and_then(|b| b.get("requestRef"))
                        .and_then(Value::as_str)
                        && let Some(&req_idx) = ctx.opened_by_ref.get(req_ref)
                        && let Some(targets) = ctx.opened_records[req_idx]
                            .payload
                            .get("body")
                            .and_then(|b| b.get("targets"))
                            .and_then(Value::as_array)
                    {
                        for t in targets {
                            if let Some(ts) = t.as_str() {
                                cov.insert(ts.to_string());
                            }
                        }
                    }
                    disclosed_targets.extend(cov.iter().cloned());
                    coverage_by_release.insert(rec.rec_ref.clone(), cov);
                }
            }
            Some(KIND_DISCLOSURE) => {
                let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
                    continue;
                };
                let outcome = body.get("outcome").and_then(Value::as_str);
                if !matches!(outcome, Some("provided" | "partial")) {
                    continue;
                }
                let excluding: BTreeSet<&str> = body
                    .get("excluding")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mut cov = BTreeSet::new();
                if let Some(prefs) = body.get("providedRefs").and_then(Value::as_array) {
                    for p in prefs {
                        if let Some(ps) = p.as_str()
                            && !excluding.contains(ps)
                        {
                            cov.insert(ps.to_string());
                        }
                    }
                }
                if let Some(scope) = body.get("scope").and_then(Value::as_str)
                    && !excluding.contains(scope)
                {
                    cov.insert(scope.to_string());
                }
                if let Some(rr_ref) = body.get("releaseRequestRef").and_then(Value::as_str)
                    && let Some(&rr_idx) = ctx.opened_by_ref.get(rr_ref)
                    && let Some(targets) = ctx.opened_records[rr_idx]
                        .payload
                        .get("body")
                        .and_then(|b| b.get("targets"))
                        .and_then(Value::as_array)
                {
                    for t in targets {
                        if let Some(ts) = t.as_str()
                            && !excluding.contains(ts)
                        {
                            cov.insert(ts.to_string());
                        }
                    }
                }
                disclosed_targets.extend(cov.iter().cloned());
                coverage_by_release.insert(rec.rec_ref.clone(), cov);
            }
            _ => {}
        }
    }

    // 10b. Level 1 unlockLog entries must reference a release/disclosure whose OWN targets cover session.
    if let Some(unlock_arr) = ctx.bundle.get("unlockLog").and_then(Value::as_array) {
        for entry in unlock_arr {
            let entry_id = entry
                .get("entryId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let session = entry
                .get("session")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let (Some(eid), Some(sess)) = (entry_id, session) else {
                findings.push(A11Finding::new(
                    3,
                    entry_id.unwrap_or("unlockLog"),
                    "checkpoint_and_unlock_log",
                    "failed",
                    "unlock_without_release_record",
                    FindingCategory::MechanicalCheck,
                    session.map(str::to_string),
                ));
                continue;
            };
            let release_ref = entry.get("releaseRef").and_then(Value::as_str);
            let matched = release_ref
                .and_then(|r| coverage_by_release.get(r))
                .is_some_and(|cov| cov.contains(sess));
            if !matched {
                findings.push(A11Finding::new(
                    3,
                    eid,
                    "checkpoint_and_unlock_log",
                    "failed",
                    "unlock_without_release_record",
                    FindingCategory::MechanicalCheck,
                    Some(sess.to_string()),
                ));
            }
        }
    }

    // 10c. Carried session plaintext (blobs or saltedContent) lacking a matching Disclosure or ReleaseReceipt.
    for rec in ctx.opened_records {
        if rec
            .kind_path()
            .as_deref()
            .is_some_and(|kp| V10C_EXCLUDED_KINDS.contains(&kp))
        {
            continue;
        }
        let Some(body) = rec.payload.get("body") else {
            continue;
        };
        let session = rec.payload.get("session").and_then(Value::as_str);

        let mut plain_refs = BTreeSet::new();
        collect_plain_bytes_refs(body, &mut plain_refs);
        for bref in plain_refs {
            if !ctx.valid_blobs.contains_key(&bref) {
                continue;
            }
            let covered = disclosed_targets.contains(&bref)
                || disclosed_targets.contains(&rec.rec_ref)
                || session.is_some_and(|s| disclosed_targets.contains(s));
            if !covered {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "checkpoint_and_unlock_log",
                    "failed",
                    "unrecorded_plaintext_in_bundle",
                    FindingCategory::MechanicalCheck,
                    Some(bref),
                ));
            }
        }

        let mut salted_refs = BTreeSet::new();
        collect_salted_refs(body, &mut salted_refs);
        for sref in salted_refs {
            if !salted_cache.get(&sref).is_some_and(Result::is_ok) {
                continue;
            }
            let covered = disclosed_targets.contains(&sref)
                || disclosed_targets.contains(&rec.rec_ref)
                || session.is_some_and(|s| disclosed_targets.contains(s));
            if !covered {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "checkpoint_and_unlock_log",
                    "failed",
                    "unrecorded_plaintext_in_bundle",
                    FindingCategory::MechanicalCheck,
                    Some(sref),
                ));
            }
        }
    }
}

fn eval_v11_definition_coexistence(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    let mut published_defs_by_kind: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_DEFINITION_PUBLISHED)
            && let Some(defs) = rec
                .payload
                .get("body")
                .and_then(|b| b.get("definitions"))
                .and_then(Value::as_array)
        {
            for d in defs {
                if let (Some(k), Some(def_ref)) = (
                    d.get("kind").and_then(Value::as_str),
                    d.get("definition").and_then(Value::as_str),
                ) {
                    published_defs_by_kind
                        .entry(k.to_string())
                        .or_default()
                        .insert(def_ref.to_string());
                }
            }
        }
    }

    for (idx, rec) in ctx.opened_records.iter().enumerate() {
        let Some(kp) = rec.kind_path() else {
            continue;
        };
        let has_coexisting_defs = published_defs_by_kind
            .get(&kp)
            .is_some_and(|set| set.len() >= 2);
        if !has_coexisting_defs {
            continue;
        }
        let Some(schema_ref) = rec.payload.get("schemaRef").and_then(Value::as_str) else {
            continue;
        };
        if ctx.base_defs.contains_index_ref(schema_ref) && ctx.body_result_by_idx[idx] == "ok" {
            findings.push(A11Finding::new(
                1,
                &rec.rec_ref,
                "definition_coexistence",
                "ok",
                "ok",
                FindingCategory::MechanicalCheck,
                Some(schema_ref.to_string()),
            ));
        }
    }
}
