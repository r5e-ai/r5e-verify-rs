use super::canonical::{
    bytes_ref_of, decode_base64, decode_strict_base64, encode_canonical_json, is_bytes_ref,
    is_salted_bytes_ref, parse_canonical_json, parse_rfc3339_instant, parse_v2_integer,
    salted_bytes_ref_of,
};
use super::crypto::{compute_keyid, verify_signature};
use super::{AvailableKey, BaseDefinitions, Finding, OpenedRecord, REPORT_FORMAT_V2, Report};
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
const KIND_DEPLOYMENT: &str = "provenance.r5e.io/v2/Deployment";
const KIND_ROOTS_CHANGED: &str = "provenance.r5e.io/v2/RootsChanged";
const KIND_DISCLOSURE: &str = "provenance.r5e.io/v2/Disclosure";
const KIND_RETENTION_HOLD: &str = "provenance.r5e.io/v2/RetentionHold";
const KIND_CHECKPOINT: &str = "provenance.r5e.io/v2/Checkpoint";
const KIND_DEFINITION_PUBLISHED: &str = "provenance.r5e.io/v2/DefinitionPublished";

const DOMAIN_RELEASE_APPROVAL: &[u8] = b"r5e-release-approval-v1\0";
const DOMAIN_WITNESS_RECEIPT: &[u8] = b"r5e-witness-receipt-v1\0";
const DOMAIN_SUCCESSION_RECOVERY: &[u8] = b"r5e-succession-recovery-v1\0";
const DOMAIN_ERASURE_PROOF: &[u8] = b"r5e-erasure-proof-v1\0";

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
pub struct A11Report {
    pub format: String,
    pub amendment: String,
    pub verdict: String,
    pub baseline: Report,
    pub a11_findings: Vec<A11Finding>,
}

impl A11Report {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("A11Report serializes to JSON Value")
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
        "identity" | "signature" | "content_hash" | "membership" | "epoch" => {
            FindingCategory::CryptographicProof
        }
        _ => FindingCategory::MechanicalCheck,
    }
}

#[derive(Debug, Default)]
struct DeploymentContract {
    custody_level: Option<i64>,
    witness_keys: BTreeSet<String>,
    approver_roles: BTreeMap<String, BTreeSet<String>>,
    sealed_service_copies: BTreeSet<String>,
}

fn extract_deployment_contract(opened_records: &[OpenedRecord]) -> DeploymentContract {
    let mut contract = DeploymentContract::default();
    let mut best_seq: i64 = -1;
    for rec in opened_records {
        let kp = rec.kind_path();
        if !matches!(kp.as_deref(), Some(KIND_DEPLOYMENT | KIND_ROOTS_CHANGED)) {
            continue;
        }
        let seq = rec
            .payload
            .get("seq")
            .and_then(parse_v2_integer)
            .unwrap_or(0);
        if seq < best_seq {
            continue;
        }
        best_seq = seq;
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        if let Some(level) = body.get("custodyLevel").and_then(parse_v2_integer) {
            contract.custody_level = Some(level);
        }
        if let Some(wkeys) = body.get("witnessKeys").and_then(Value::as_array) {
            contract.witness_keys = wkeys
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
                    map.insert(role.to_string(), set);
                }
            }
            contract.approver_roles = map;
        }
        if let Some(copies) = body.get("sealedServiceCopies").and_then(Value::as_array) {
            contract.sealed_service_copies = copies
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
        }
    }
    contract
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
    if compute_keyid(&akey.algorithm, &akey.bytes).as_deref() != Some(keyid) {
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

fn is_person_uri(uri: &str) -> bool {
    uri.starts_with("urn:r5e:subject:") || uri.starts_with("urn:r5e:person:")
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

pub(crate) struct A11EvalContext<'a> {
    pub bundle: &'a Value,
    pub opened_records: &'a [OpenedRecord],
    pub opened_by_ref: &'a BTreeMap<String, usize>,
    pub body_result_by_idx: &'a [String],
    pub available_keys: &'a BTreeMap<String, AvailableKey>,
    pub valid_blobs: &'a BTreeMap<String, Vec<u8>>,
    pub base_defs: &'a BaseDefinitions,
}

pub(crate) fn evaluate_a11(ctx: &A11EvalContext<'_>, baseline: Report) -> A11Report {
    let mut findings: Vec<A11Finding> = Vec::new();
    let contract = extract_deployment_contract(ctx.opened_records);

    // Index Endorsement records by subject keyid.
    let mut endorsements_by_subject: BTreeMap<String, Vec<&OpenedRecord>> = BTreeMap::new();
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_ENDORSEMENT)
            && let Some(subj) = rec
                .payload
                .get("body")
                .and_then(|b| b.get("subject"))
                .and_then(Value::as_str)
        {
            endorsements_by_subject
                .entry(subj.to_string())
                .or_default()
                .push(rec);
        }
    }

    // Index BasisOverlay records by basisRef.
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

    // V1: basis_signatures
    eval_v1_basis_signatures(ctx, &mut findings);

    // V2: basis_declared_power
    eval_v2_basis_declared_power(ctx, &mut findings);

    // V3: basis_overlay_order
    eval_v3_basis_overlay_order(ctx, &overlays_by_basis, &mut findings);

    // V4: release_request_approvals
    eval_v4_release_request_approvals(ctx, &contract, &endorsements_by_subject, &mut findings);

    // V5: witness_receipt_binding
    eval_v5_witness_receipt_binding(ctx, &contract, &mut findings);

    // V6: release_receipt_fingerprint
    eval_v6_release_receipt_fingerprint(ctx, &contract, &mut findings);

    // V7: succession_recovery
    eval_v7_succession_recovery(ctx, &mut findings);

    // V8: erasure_l2_proof
    eval_v8_erasure_l2_proof(ctx, &contract, &mut findings);

    // V9: salted_content_ref
    eval_v9_salted_content_ref(ctx, &mut findings);

    // V10: checkpoint_and_unlock_log
    eval_v10_checkpoint_and_unlock_log(ctx, &mut findings);

    // V11: definition_coexistence
    eval_v11_definition_coexistence(ctx, &mut findings);

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

    let verdict = if baseline.summary.failed > 0 || findings.iter().any(|f| f.result == "failed") {
        "failed"
    } else if findings.iter().any(|f| f.result == "incomplete") {
        "incomplete"
    } else {
        "ok"
    };

    A11Report {
        format: REPORT_FORMAT_V2.to_string(),
        amendment: AMENDMENT_A11.to_string(),
        verdict: verdict.to_string(),
        baseline,
        a11_findings: findings,
    }
}

fn eval_v1_basis_signatures(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_BASIS) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let subjects_non_empty = body
            .get("subjects")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        let has_rep = body.get("representative").is_some_and(|v| !v.is_null());
        let actor_is_person = body
            .get("actor")
            .and_then(Value::as_str)
            .is_some_and(is_person_uri);
        let names_person = subjects_non_empty || has_rep || actor_is_person;

        let distinct_signers: BTreeSet<&str> = rec.signers.iter().map(String::as_str).collect();
        if names_person {
            if distinct_signers.len() == 2 && rec.all_sigs_ok {
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
        } else if !distinct_signers.is_empty() && rec.all_sigs_ok {
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
}

fn eval_v2_basis_declared_power(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    for rec in ctx.opened_records {
        let kp = rec.kind_path();
        if !matches!(
            kp.as_deref(),
            Some(KIND_RELEASE_REQUEST | KIND_DISCLOSURE | KIND_RETENTION_HOLD)
        ) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let Some(basis_ref) = body.get("basisRef").and_then(Value::as_str) else {
            continue;
        };
        let Some(&target_idx) = ctx.opened_by_ref.get(basis_ref) else {
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
            }
            continue;
        }

        if target_kp.as_deref() != Some(KIND_BASIS) {
            continue;
        }
        let Some(basis_body) = target_rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };

        // For ReleaseRequest, check groundId and power.
        if kp.as_deref() == Some(KIND_RELEASE_REQUEST) {
            let Some(ground_id) = body.get("groundId").and_then(Value::as_str) else {
                continue;
            };
            let power = body
                .get("power")
                .and_then(Value::as_str)
                .unwrap_or("disclose");

            // Reject citing a declaredTerms entry.
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
                        .any(|p| p.get("power").and_then(Value::as_str) == Some(power))
                });
            if !has_power {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "basis_declared_power",
                    "failed",
                    "act_cites_declared_or_absent_power",
                    FindingCategory::MechanicalCheck,
                    Some(power.to_string()),
                ));
                continue;
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
}

fn eval_v3_basis_overlay_order(
    ctx: &A11EvalContext<'_>,
    overlays_by_basis: &BTreeMap<String, Vec<&OpenedRecord>>,
    findings: &mut Vec<A11Finding>,
) {
    for rec in ctx.opened_records {
        let kp = rec.kind_path();
        if !matches!(
            kp.as_deref(),
            Some(KIND_RELEASE_REQUEST | KIND_DISCLOSURE | KIND_RETENTION_HOLD)
        ) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let Some(basis_ref) = body.get("basisRef").and_then(Value::as_str) else {
            continue;
        };
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

        // Check withdrawal overlays in canonical order.
        if let Some(overlays) = overlays_by_basis.get(basis_ref) {
            let mut sorted_overlays: Vec<&OpenedRecord> = overlays.clone();
            sorted_overlays.sort_by(|a, b| {
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

            let active_withdrawal = sorted_overlays.iter().find(|ov| {
                let ov_body = ov.payload.get("body");
                let is_wd = ov_body
                    .and_then(|b| b.get("overlayType"))
                    .and_then(Value::as_str)
                    == Some("withdrawal");
                if !is_wd {
                    return false;
                }
                let eff = ov_body
                    .and_then(|b| b.get("effectiveAt"))
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false));
                eff.is_some_and(|t| t <= act_time)
            });

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
        }

        // Check duration.until on the cited ground/power if applicable.
        if kp.as_deref() == Some(KIND_RELEASE_REQUEST)
            && let Some(ground_id) = body.get("groundId").and_then(Value::as_str)
        {
            let power = body
                .get("power")
                .and_then(Value::as_str)
                .unwrap_or("disclose");
            let until_opt = basis_rec
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
                .and_then(|p| p.get("duration"))
                .and_then(|d| d.get("until"))
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339_instant(s, None, false));
            if let Some(until_time) = until_opt
                && act_time > until_time
            {
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

fn eval_v4_release_request_approvals(
    ctx: &A11EvalContext<'_>,
    contract: &DeploymentContract,
    endorsements_by_subject: &BTreeMap<String, Vec<&OpenedRecord>>,
    findings: &mut Vec<A11Finding>,
) {
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_RELEASE_REQUEST) {
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

        let basis_rec = ctx
            .opened_by_ref
            .get(basis_ref)
            .map(|&idx| &ctx.opened_records[idx])
            .filter(|r| r.kind_path().as_deref() == Some(KIND_BASIS));

        // 1. Check ReleaseRequest.subjects completeness against Basis.subjects.
        if let Some(brec) = basis_rec {
            let basis_subjects: BTreeSet<&str> = brec
                .payload
                .get("body")
                .and_then(|b| b.get("subjects"))
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let req_subjects: BTreeSet<&str> = body
                .get("subjects")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if let Some(&missing) = basis_subjects.difference(&req_subjects).next() {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "release_subjects_incomplete",
                    FindingCategory::MechanicalCheck,
                    Some(missing.to_string()),
                ));
                continue;
            }
            if let Some(&extra) = req_subjects.difference(&basis_subjects).next() {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_request_approvals",
                    "failed",
                    "release_subjects_incomplete",
                    FindingCategory::MechanicalCheck,
                    Some(extra.to_string()),
                ));
                continue;
            }
        }

        // 2. Verify every approval signature and hardware keyStorage endorsement.
        let Some(approvals) = body.get("approvals").and_then(Value::as_array) else {
            continue;
        };
        let approval_msg = json!({
            "basisFingerprint": basis_ref,
            "contractVersion": contract_version,
            "recipientKey": recipient_key,
            "requestId": request_id,
        });

        let mut failed = false;
        let mut all_hw_attested = true;
        let mut valid_signers_by_role: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut first_valid_signer: Option<String> = None;

        for app in approvals {
            let (Some(signer_key), Some(role), Some(sig_b64)) = (
                app.get("signerKey").and_then(Value::as_str),
                app.get("role").and_then(Value::as_str),
                app.get("signature").and_then(Value::as_str),
            ) else {
                failed = true;
                break;
            };

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

            // Look up Endorsement for signer_key.
            let matching_endorsement = endorsements_by_subject
                .get(signer_key)
                .and_then(|list| list.last().copied());
            let key_storage = matching_endorsement
                .and_then(|e| e.payload.get("body"))
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

            let has_attested_hw = matching_endorsement
                .and_then(|e| e.payload.get("body"))
                .and_then(|b| b.get("hardwareAttestationRef"))
                .and_then(Value::as_str)
                .is_some_and(|aref| ctx.valid_blobs.contains_key(aref));
            if !has_attested_hw {
                all_hw_attested = false;
            }

            let role_allowed_by_contract = contract
                .approver_roles
                .get(role)
                .is_none_or(|keys| keys.contains(signer_key));
            if role_allowed_by_contract {
                valid_signers_by_role
                    .entry(role.to_string())
                    .or_default()
                    .insert(signer_key.to_string());
            }
            if first_valid_signer.is_none() {
                first_valid_signer = Some(signer_key.to_string());
            }
        }

        if failed {
            continue;
        }

        // 3. Check approvalRule threshold when cited Basis ground/power exists.
        if let (Some(brec), Some(ground_id)) =
            (basis_rec, body.get("groundId").and_then(Value::as_str))
        {
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
                    .max(1) as usize;
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
                if distinct_qualifying.len() < threshold {
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

        let category = if all_hw_attested {
            FindingCategory::CryptographicProof
        } else {
            FindingCategory::InstitutionalAssertion
        };
        findings.push(A11Finding::new(
            2,
            &rec.rec_ref,
            "release_request_approvals",
            "ok",
            "ok",
            category,
            first_valid_signer,
        ));
    }
}

fn eval_v5_witness_receipt_binding(
    ctx: &A11EvalContext<'_>,
    contract: &DeploymentContract,
    findings: &mut Vec<A11Finding>,
) {
    let witness_receipts = ctx.bundle.get("witnessReceipts").and_then(Value::as_object);

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

        // Check map key == bytes:sha256:sha256(canonical_json(receipt)).
        let key_matches =
            encode_canonical_json(receipt).is_some_and(|c| bytes_ref_of(c.as_bytes()) == w_ref);
        if !key_matches {
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
                &rec.rec_ref,
                "witness_receipt_binding",
                "failed",
                "witness_receipt_hash_mismatch",
                FindingCategory::CryptographicProof,
                Some(w_ref.to_string()),
            ));
            continue;
        };

        // Check pinned witnessKey.
        if !contract.witness_keys.contains(witness_key) {
            findings.push(A11Finding::new(
                3,
                &rec.rec_ref,
                "witness_receipt_binding",
                "failed",
                "witness_unpinned",
                FindingCategory::CryptographicProof,
                Some(witness_key.to_string()),
            ));
            continue;
        }

        // Check requestRef and requestHash == sha256(canonical(ReleaseRequest)).
        let expected_hash = req_ref
            .strip_prefix("evidence:sha256:")
            .map(|h| format!("sha256:{h}"));
        if rcpt_req_ref != req_ref || expected_hash.as_deref() != Some(req_hash) {
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
        }

        // Verify signature over domain-separated canonical unsigned receipt.
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
                &rec.rec_ref,
                "witness_receipt_binding",
                "failed",
                "witness_receipt_hash_mismatch",
                FindingCategory::CryptographicProof,
                Some(w_ref.to_string()),
            ));
            continue;
        }

        findings.push(A11Finding::new(
            3,
            &rec.rec_ref,
            "witness_receipt_binding",
            "ok",
            "ok",
            FindingCategory::CryptographicProof,
            Some(w_ref.to_string()),
        ));
    }
}

fn eval_v6_release_receipt_fingerprint(
    ctx: &A11EvalContext<'_>,
    contract: &DeploymentContract,
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
            continue;
        }

        let expects_fp = matches!(outcome, "released" | "delivered");
        if expects_fp {
            if let Some(fp_str) = fp {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_receipt_fingerprint",
                    "ok",
                    "ok",
                    FindingCategory::MechanicalCheck,
                    Some(fp_str.to_string()),
                ));
            } else {
                findings.push(A11Finding::new(
                    2,
                    &rec.rec_ref,
                    "release_receipt_fingerprint",
                    "failed",
                    "released_fingerprint_missing",
                    FindingCategory::MechanicalCheck,
                    None,
                ));
            }
        } else if let Some(fp_str) = fp {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_receipt_fingerprint",
                "failed",
                "released_fingerprint_missing",
                FindingCategory::MechanicalCheck,
                Some(fp_str.to_string()),
            ));
        } else {
            findings.push(A11Finding::new(
                2,
                &rec.rec_ref,
                "release_receipt_fingerprint",
                "ok",
                "ok",
                FindingCategory::MechanicalCheck,
                None,
            ));
        }
    }
}

fn eval_v7_succession_recovery(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_SUCCESSION) {
            continue;
        }
        let Some(body) = rec.payload.get("body").and_then(Value::as_object) else {
            continue;
        };
        let (Some(predecessor), Some(successor)) = (
            body.get("predecessor").and_then(Value::as_str),
            body.get("successor").and_then(Value::as_str),
        ) else {
            continue;
        };

        let Some(rp) = body.get("recoveryProof").and_then(Value::as_object) else {
            // Standard dual-key succession form.
            let std_ok = rec.all_sigs_ok
                && rec.signers.len() == 2
                && rec.signers[0] == predecessor
                && rec.signers[1] == successor;
            if std_ok {
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
                    "succession_recovery_threshold_not_met",
                    FindingCategory::CryptographicProof,
                    None,
                ));
            }
            continue;
        };

        // Recovery form: successor must sign the Succession envelope.
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

        let rule_obj = ctx
            .opened_by_ref
            .get(rule_ref)
            .map(|&idx| &ctx.opened_records[idx])
            .filter(|r| {
                r.kind_path().as_deref() == Some(KIND_ENDORSEMENT)
                    && r.payload
                        .get("body")
                        .and_then(|b| b.get("subject"))
                        .and_then(Value::as_str)
                        == Some(predecessor)
            })
            .and_then(|r| r.payload.get("body"))
            .and_then(|b| b.get("recoveryRule"))
            .and_then(Value::as_object);

        let Some(rule) = rule_obj else {
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

        let threshold = rule
            .get("threshold")
            .and_then(parse_v2_integer)
            .unwrap_or(1)
            .max(1) as usize;
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
                    ctx.available_keys,
                )
            {
                valid_signers.insert(sk);
            }
        }

        let succ_sig_ok = rec.all_sigs_ok && rec.signers.len() == 1 && rec.signers[0] == successor;
        if succ_sig_ok && valid_signers.len() >= threshold {
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
                "succession_recovery_threshold_not_met",
                FindingCategory::CryptographicProof,
                None,
            ));
        }
    }
}

fn eval_v8_erasure_l2_proof(
    ctx: &A11EvalContext<'_>,
    contract: &DeploymentContract,
    findings: &mut Vec<A11Finding>,
) {
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() != Some(KIND_ERASURE_ANSWER) {
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
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "ok",
                    "ok",
                    FindingCategory::InstitutionalAssertion,
                    Some(session.to_string()),
                ));
                continue;
            }

            if ev_support != "sealed_key_service_proof" {
                continue;
            }

            let confirmed: Vec<&str> = entry
                .get("confirmedCopies")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();

            // Check that every confirmed copy belongs to contract.sealed_service_copies.
            if let Some(&unknown) = confirmed
                .iter()
                .find(|&&cid| !contract.sealed_service_copies.contains(cid))
            {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "failed",
                    "erasure_unknown_copy_id",
                    FindingCategory::CryptographicProof,
                    Some(unknown.to_string()),
                ));
                continue;
            }

            // Load and parse proofRef blob.
            let proof_val = entry
                .get("proofRef")
                .and_then(Value::as_str)
                .and_then(|pref| ctx.valid_blobs.get(pref))
                .and_then(|raw| parse_canonical_json(raw));
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

            // Verify proof signature for every copy listed in confirmedCopies.
            let mut bad_copy: Option<String> = None;
            for &copy_id in &confirmed {
                let matching_conf = confs
                    .iter()
                    .find(|c| c.get("copyId").and_then(Value::as_str) == Some(copy_id));
                let verified = matching_conf.is_some_and(|c| {
                    let (Some(kid), Some(sig_b64)) = (
                        c.get("keyId").and_then(Value::as_str),
                        c.get("signature").and_then(Value::as_str),
                    ) else {
                        return false;
                    };
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
                });
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

            // Check whether any contract copy has not yet confirmed.
            let confirmed_set: BTreeSet<&str> = confirmed.into_iter().collect();
            if let Some(pending) = contract
                .sealed_service_copies
                .iter()
                .find(|c| !confirmed_set.contains(c.as_str()))
            {
                findings.push(A11Finding::new(
                    3,
                    &rec.rec_ref,
                    "erasure_l2_proof",
                    "incomplete",
                    "erasure_copy_confirmation_pending",
                    FindingCategory::CryptographicProof,
                    Some(pending.clone()),
                ));
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

fn eval_v9_salted_content_ref(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    let salted_map = ctx.bundle.get("saltedContent").and_then(Value::as_object);

    for rec in ctx.opened_records {
        let Some(body) = rec.payload.get("body") else {
            continue;
        };
        let mut refs = BTreeSet::new();
        collect_salted_refs(body, &mut refs);
        for s_ref in refs {
            let Some(entry) = salted_map.and_then(|m| m.get(&s_ref)) else {
                findings.push(A11Finding::new(
                    1,
                    &rec.rec_ref,
                    "salted_content_ref",
                    "incomplete",
                    "unavailable_evidence",
                    FindingCategory::UnavailableEvidence,
                    Some(s_ref),
                ));
                continue;
            };
            let decoded = (|| -> Option<(Vec<u8>, Vec<u8>)> {
                let salt_b64 = entry.get("salt")?.as_str()?;
                let bytes_b64 = entry.get("bytes")?.as_str()?;
                let salt = decode_base64(salt_b64)?;
                if salt.len() != 32 {
                    return None;
                }
                let plaintext = decode_base64(bytes_b64)?;
                Some((salt, plaintext))
            })();
            let matches = decoded
                .is_some_and(|(salt, plaintext)| salted_bytes_ref_of(&salt, &plaintext) == s_ref);
            if matches {
                findings.push(A11Finding::new(
                    1,
                    &rec.rec_ref,
                    "salted_content_ref",
                    "ok",
                    "ok",
                    FindingCategory::CryptographicProof,
                    Some(s_ref),
                ));
            } else {
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

fn eval_v10_checkpoint_and_unlock_log(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    // 10a. Pinned checkpoints and monotonicity.
    let mut checkpoints_by_seq: BTreeMap<i64, Vec<&OpenedRecord>> = BTreeMap::new();
    for rec in ctx.opened_records {
        if rec.kind_path().as_deref() == Some(KIND_CHECKPOINT)
            && let Some(seq) = rec.payload.get("seq").and_then(parse_v2_integer)
        {
            checkpoints_by_seq.entry(seq).or_default().push(rec);
        }
    }

    if let Some(pinned_arr) = ctx
        .bundle
        .get("pinnedCheckpoints")
        .and_then(Value::as_array)
    {
        for pin in pinned_arr {
            let (Some(pinned_ref), Some(pinned_seq)) = (
                pin.get("ref").and_then(Value::as_str),
                pin.get("seq").and_then(parse_v2_integer),
            ) else {
                continue;
            };
            match checkpoints_by_seq.get(&pinned_seq) {
                Some(ckpts) => {
                    for ckpt in ckpts {
                        if ckpt.rec_ref != pinned_ref {
                            findings.push(A11Finding::new(
                                3,
                                &ckpt.rec_ref,
                                "checkpoint_and_unlock_log",
                                "failed",
                                "checkpoint_fork_or_stale",
                                FindingCategory::CryptographicProof,
                                Some(pinned_ref.to_string()),
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
                        Some(pinned_ref.to_string()),
                    ));
                }
            }
        }
    }

    // Check monotonic checkpoint sequence order in bundle.checkpoints.
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

    // Collect valid release/disclosure records and their covered sessions/targets/refs.
    let mut valid_release_refs: BTreeSet<String> = BTreeSet::new();
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
                    valid_release_refs.insert(rec.rec_ref.clone());
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
                                disclosed_targets.insert(ts.to_string());
                            }
                        }
                    }
                }
            }
            Some(KIND_DISCLOSURE) => {
                valid_release_refs.insert(rec.rec_ref.clone());
                if let Some(body) = rec.payload.get("body") {
                    if let Some(targets) = body.get("targets").and_then(Value::as_array) {
                        for t in targets {
                            if let Some(ts) = t.as_str() {
                                disclosed_targets.insert(ts.to_string());
                            }
                        }
                    }
                    if let Some(sess) = rec.payload.get("session").and_then(Value::as_str) {
                        disclosed_targets.insert(sess.to_string());
                    }
                    let mut refs = BTreeSet::new();
                    collect_plain_bytes_refs(body, &mut refs);
                    disclosed_targets.extend(refs);
                }
            }
            _ => {}
        }
    }

    // 10b. Level 1 unlockLog entries lacking a matching release record.
    if let Some(unlock_arr) = ctx.bundle.get("unlockLog").and_then(Value::as_array) {
        for entry in unlock_arr {
            let (Some(entry_id), Some(session)) = (
                entry.get("entryId").and_then(Value::as_str),
                entry.get("session").and_then(Value::as_str),
            ) else {
                continue;
            };
            let release_ref = entry.get("releaseRef").and_then(Value::as_str);
            let matched = release_ref.is_some_and(|r| valid_release_refs.contains(r))
                && disclosed_targets.contains(session);
            if !matched {
                findings.push(A11Finding::new(
                    3,
                    entry_id,
                    "checkpoint_and_unlock_log",
                    "failed",
                    "unlock_without_release_record",
                    FindingCategory::MechanicalCheck,
                    Some(session.to_string()),
                ));
            }
        }
    }

    // 10c. Carried session plaintext payloads lacking a matching Disclosure or ReleaseReceipt.
    for rec in ctx.opened_records {
        let Some(session) = rec.payload.get("session").and_then(Value::as_str) else {
            continue;
        };
        if matches!(
            rec.kind_path().as_deref(),
            Some(
                KIND_DISCLOSURE | KIND_RELEASE_RECEIPT | KIND_RELEASE_REQUEST | KIND_ERASURE_ANSWER
            )
        ) {
            continue;
        }
        let Some(body) = rec.payload.get("body") else {
            continue;
        };
        let mut refs = BTreeSet::new();
        collect_plain_bytes_refs(body, &mut refs);
        for bref in refs {
            if !ctx.valid_blobs.contains_key(&bref) {
                continue;
            }
            let covered = disclosed_targets.contains(&bref)
                || disclosed_targets.contains(&rec.rec_ref)
                || disclosed_targets.contains(session);
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
    }
}

fn eval_v11_definition_coexistence(ctx: &A11EvalContext<'_>, findings: &mut Vec<A11Finding>) {
    // Collect distinct published schemaRefs per kind across DefinitionPublished records.
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
