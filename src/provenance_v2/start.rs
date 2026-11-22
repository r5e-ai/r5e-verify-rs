use super::authority::{self, RootTenure};
use super::canonical::{UtcInstant, parse_rfc3339_instant, parse_v2_integer};
use super::{Finding, OpenedRecord, PublisherTrust, VerifyOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const KIND_CHAIN_STARTED: &str = "provenance.r5e.io/v2/ChainStarted";
pub const KIND_DEPLOYMENT: &str = "provenance.r5e.io/v2/Deployment";
pub const KIND_ROOTS_CHANGED: &str = "provenance.r5e.io/v2/RootsChanged";
pub const KIND_ROOT_CHANGE_APPROVAL: &str = "provenance.r5e.io/v2/RootChangeApproval";
pub const KIND_PRINCIPAL: &str = "provenance.r5e.io/v2/Principal";
pub const KIND_ENDORSEMENT: &str = "provenance.r5e.io/v2/Endorsement";
pub const KIND_REVOCATION: &str = "provenance.r5e.io/v2/Revocation";
pub const KIND_DEFINITION_PUBLISHED: &str = "provenance.r5e.io/v2/DefinitionPublished";

pub const START_STREAM_KINDS: &[&str] = &[KIND_CHAIN_STARTED, KIND_DEPLOYMENT, KIND_ROOTS_CHANGED];

/// Optional top-level `"start"` report member (`A6-start-schemas-and-codes.md` §2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSummary {
    pub chain: Option<String>,
    pub deployment: String,
    pub head_captured_at: String,
    pub head_ref: String,
    pub head_seq: i64,
    pub stream: String,
}

#[derive(Debug, Clone)]
pub(crate) enum PinnedChainOutcome {
    NotPinned,
    Established(Vec<RootTenure>),
    Incomplete,
    Failed,
}

pub(crate) struct StartEvaluation {
    pub(crate) findings: Vec<Finding>,
    pub(crate) report_start: Option<StartSummary>,
    pub(crate) pinned_outcome: PinnedChainOutcome,
    pub(crate) trusted_roots_tenures: Vec<RootTenure>,
}

#[derive(Debug, Clone)]
struct OkApprovalInfo {
    root: String,
    custodian: String,
    custodian_key: String,
}

/// Candidate start stream URI pattern (`^urn:r5e:stream:[^:]+:start$`, `A6` §4.2).
pub fn is_candidate_start_stream_uri(s: &str) -> bool {
    s.strip_prefix("urn:r5e:stream:")
        .and_then(|rest| rest.strip_suffix(":start"))
        .is_some_and(|mid| !mid.is_empty() && !mid.contains(':'))
}

/// Strict deployment start stream URI pattern (`^urn:r5e:stream:[a-z0-9][a-z0-9-]*:start$`, `A6` §4.2 Row 3).
pub fn is_valid_start_stream_uri(s: &str) -> bool {
    s.strip_prefix("urn:r5e:stream:")
        .and_then(|rest| rest.strip_suffix(":start"))
        .is_some_and(|slug| {
            let b = slug.as_bytes();
            !b.is_empty()
                && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                && b[1..]
                    .iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn extract_definition_pairs(
    defs: &[Value],
    reject_duplicate_kinds: bool,
) -> Option<BTreeSet<(&str, &str)>> {
    let mut seen_kinds = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for item in defs {
        let k = item.get("kind")?.as_str()?;
        let d = item.get("definition")?.as_str()?;
        if reject_duplicate_kinds && !seen_kinds.insert(k) {
            return None;
        }
        pairs.insert((k, d));
    }
    Some(pairs)
}

/// Tightened `publication` check for `provenance.r5e.io/v2/ChainStarted` (`A6` §3 & `A9` §4).
/// Returns `None` when `body` is not `"ok"` (or lacks base `ChainStarted` fields),
/// signaling the caller to evaluate §6.2a's ordinary publication table.
pub(crate) fn check_chain_started_publication(
    rec_idx: usize,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    publisher_trust: &PublisherTrust,
) -> Option<Finding> {
    let rec = &opened_records[rec_idx];
    if rec.kind_path().as_deref() != Some(KIND_CHAIN_STARTED) {
        return None;
    }
    if body_result_by_idx[rec_idx] != "ok" {
        return None;
    }

    let body = rec.payload.get("body")?;
    let p_ref = body.get("publication")?.as_str()?;
    let p_pub = body.get("publisher")?.as_str()?;
    let d_list = body.get("definitions")?.as_array()?;

    // Row 1: `P_ref` is not among opened records.
    let Some(&p_idx) = opened_by_ref.get(p_ref) else {
        return Some(Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "incomplete",
            "publication_not_carried",
            Some(p_ref.to_string()),
        ));
    };

    let p_rec = &opened_records[p_idx];

    // Row 2: `P` is not `DefinitionPublished`, `P`'s `body` finding is not `ok`,
    // `P.issuer != P_pub`, or any `signature` finding of `P` is `failed`.
    if p_rec.kind_path().as_deref() != Some(KIND_DEFINITION_PUBLISHED)
        || body_result_by_idx[p_idx] != "ok"
        || p_rec.signers[0] != p_pub
        || any_sig_failed_by_idx[p_idx]
    {
        return Some(Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "failed",
            "cited_publication_mismatch",
            Some(p_ref.to_string()),
        ));
    }

    // Row 3: Some `signature` finding of `P` is `incomplete` (and none `failed`).
    if !p_rec.all_sigs_ok {
        return Some(Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "incomplete",
            "publication_not_verified",
            Some(p_ref.to_string()),
        ));
    }

    // Row 4: `D_list` has duplicate `kind` entries, the set of `(kind, definition)` pairs
    // in `D_list` does not equal that of `P.body.definitions`, or `D_list` does not map
    // `"provenance.r5e.io/v2/ChainStarted"` to this record's own `schemaRef`.
    let d_pairs_opt = extract_definition_pairs(d_list, true);
    let p_pairs_opt = p_rec
        .payload
        .get("body")
        .and_then(|b| b.get("definitions"))
        .and_then(Value::as_array)
        .and_then(|pa| extract_definition_pairs(pa, false));
    let own_schema_ref = rec.payload.get("schemaRef").and_then(Value::as_str);

    let definitions_match = match (d_pairs_opt, p_pairs_opt, own_schema_ref) {
        (Some(d_pairs), Some(p_pairs), Some(sr)) => {
            d_pairs == p_pairs && d_pairs.contains(&(KIND_CHAIN_STARTED, sr))
        }
        _ => false,
    };
    if !definitions_match {
        return Some(Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "failed",
            "definitions_differ_from_publication",
            Some(p_ref.to_string()),
        ));
    }

    // Row 5 (`A6` §3 & `A9` §4): `P_pub` must be believed about every kind listed in `ChainStarted`.
    let believed_for_all = publisher_trust.contains_publisher(p_pub)
        && d_list.iter().all(|item| {
            item.get("kind")
                .and_then(Value::as_str)
                .is_some_and(|k| publisher_trust.believes(p_pub, k))
        });
    if !believed_for_all {
        return Some(Finding::new(
            2,
            &rec.rec_ref,
            "publication",
            "incomplete",
            "publisher_not_trusted",
            Some(p_ref.to_string()),
        ));
    }

    // Row 6: Otherwise `ok`.
    Some(Finding::new(
        2,
        &rec.rec_ref,
        "publication",
        "ok",
        "ok",
        Some(p_ref.to_string()),
    ))
}

/// Tightened terms check (`A6` Slice 2 §3.2 clauses 1–6) shared by `Deployment` (Row 11)
/// and `RootsChanged` (Row 20).
fn terms_hold(body: &Value, roots: &[Value], threshold: i64, claimed_by: Option<&str>) -> bool {
    if roots.is_empty() || threshold < 1 || (threshold as usize) > roots.len() {
        return false;
    }

    let mut root_keys: BTreeSet<&str> = BTreeSet::new();
    for r in roots {
        let Some(k) = r.get("key").and_then(Value::as_str) else {
            return false;
        };
        if !root_keys.insert(k) {
            return false;
        }
        // Clause 6: no root entry declares `holder == "agent"`.
        if r.get("holder").and_then(Value::as_str) == Some("agent") {
            return false;
        }
    }

    if let Some(cb) = claimed_by
        && !root_keys.contains(cb)
    {
        return false;
    }

    let mut recovery_keys: BTreeSet<&str> = BTreeSet::new();
    if let Some(rk_val) = body.get("recoveryKeys") {
        let Some(rk_arr) = rk_val.as_array() else {
            return false;
        };
        for item in rk_arr {
            let Some(rk) = item.as_str() else {
                return false;
            };
            if !recovery_keys.insert(rk) || root_keys.contains(rk) {
                return false;
            }
        }
    }

    if let Some(cust_val) = body.get("custodians") {
        let Some(cust_arr) = cust_val.as_array() else {
            return false;
        };
        let mut seen_identities: BTreeSet<&str> = BTreeSet::new();
        let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
        for item in cust_arr {
            let Some(obj) = item.as_object() else {
                return false;
            };
            let Some(id) = obj.get("identity").and_then(Value::as_str) else {
                return false;
            };
            if !seen_identities.insert(id) {
                return false;
            }
            if let Some(kv) = obj.get("key") {
                let Some(ks) = kv.as_str() else {
                    return false;
                };
                // Clauses 4 & 5: unique custodian keys, disjoint from `roots` and `recoveryKeys`.
                if !seen_keys.insert(ks) || root_keys.contains(ks) || recovery_keys.contains(ks) {
                    return false;
                }
            }
        }
    }

    true
}

fn count_veto_free_quorum(ok_approvals: &[OkApprovalInfo]) -> usize {
    let mut pairs_by_root: BTreeMap<&str, BTreeSet<(&str, &str)>> = BTreeMap::new();
    let mut roots_by_custodian: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut roots_by_key: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for app in ok_approvals {
        let r = app.root.as_str();
        let c = app.custodian.as_str();
        let k = app.custodian_key.as_str();
        pairs_by_root.entry(r).or_default().insert((c, k));
        roots_by_custodian.entry(c).or_default().insert(r);
        roots_by_key.entry(k).or_default().insert(r);
    }

    let mut count = 0;
    for (&r, pairs) in &pairs_by_root {
        if pairs.len() != 1 {
            continue;
        }
        let &(c, k) = pairs.iter().next().unwrap();
        let cust_unique = roots_by_custodian
            .get(c)
            .is_some_and(|rs| rs.len() == 1 && rs.contains(r));
        let key_unique = roots_by_key
            .get(k)
            .is_some_and(|rs| rs.len() == 1 && rs.contains(r));
        if cust_unique && key_unique {
            count += 1;
        }
    }
    count
}

/// Evaluates an off-start-stream `RootChangeApproval` record (`A6` Slice 2 §3.3 Rows A1–A15 & §3.5).
#[allow(clippy::too_many_arguments)]
fn evaluate_off_stream_approval(
    a_idx: usize,
    stream_record_counts: &BTreeMap<&str, usize>,
    candidate_streams: &BTreeSet<String>,
    by_stream_seq: &BTreeMap<String, BTreeMap<i64, Vec<usize>>>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    agent_principal_keys: &BTreeSet<&str>,
    start_finding_by_idx: &BTreeMap<usize, Finding>,
) -> (Finding, Option<(String, OkApprovalInfo)>) {
    let a_rec = &opened_records[a_idx];

    // Row A1: `A`'s `body` finding is `failed` or any `signature` finding of `A` is `failed`.
    if body_result_by_idx[a_idx] == "failed" || any_sig_failed_by_idx[a_idx] {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "invalid_root_change_approval",
                None,
            ),
            None,
        );
    }

    // Row A2: `A`'s `body` finding is `incomplete` or any `signature` finding of `A` is `incomplete`.
    if body_result_by_idx[a_idx] != "ok" || !a_rec.all_sigs_ok {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "incomplete",
                "unverified_root_change_approval",
                None,
            ),
            None,
        );
    }

    // Row A3: `A.seq != 1`, or another opened record in the bundle has `stream == A.stream`.
    let a_stream = a_rec.payload.get("stream").and_then(Value::as_str);
    let a_seq = a_rec.payload.get("seq").and_then(parse_v2_integer);
    if a_seq != Some(1)
        || a_stream.is_none_or(|s| stream_record_counts.get(s).copied().unwrap_or(0) > 1)
    {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approval_not_alone_on_stream",
                a_stream.map(str::to_string),
            ),
            None,
        );
    }

    let Some(a_body) = a_rec.payload.get("body") else {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "invalid_root_change_approval",
                None,
            ),
            None,
        );
    };
    let (Some(change_ref), Some(a_root), Some(a_custodian), Some(a_custodian_key), Some(a_cap)) = (
        a_body.get("change").and_then(Value::as_str),
        a_body.get("root").and_then(Value::as_str),
        a_body.get("custodian").and_then(Value::as_str),
        a_body.get("custodianKey").and_then(Value::as_str),
        a_rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false)),
    ) else {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "invalid_root_change_approval",
                None,
            ),
            None,
        );
    };

    // Row A4: `A.body.change` is not among opened records.
    let Some(&r_idx) = opened_by_ref.get(change_ref) else {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "incomplete",
                "approved_change_not_carried",
                Some(change_ref.to_string()),
            ),
            None,
        );
    };
    let r_rec = &opened_records[r_idx];

    // Row A5: Opened `R = record(A.body.change)` is not a `RootsChanged` on the single non-forked
    // candidate start stream at `seq >= 3`, or `R`'s `body` is `failed`, or (`R`'s `body` is `ok`
    // and `R.body.authorization != "quorum"`).
    let single_stream_opt = if candidate_streams.len() == 1 {
        candidate_streams.iter().next().map(String::as_str)
    } else {
        None
    };
    let r_stream = r_rec.payload.get("stream").and_then(Value::as_str);
    let r_seq_opt = r_rec.payload.get("seq").and_then(parse_v2_integer);
    let r_on_valid_nonforked_start = match (single_stream_opt, r_stream, r_seq_opt) {
        (Some(ss), Some(rs), Some(r_seq))
            if ss == rs && is_valid_start_stream_uri(ss) && r_seq >= 3 =>
        {
            by_stream_seq
                .get(ss)
                .and_then(|m| m.get(&r_seq))
                .is_some_and(|v| v.len() == 1)
        }
        _ => false,
    };
    let r_body_status = body_result_by_idx[r_idx].as_str();
    let r_auth_not_quorum = r_body_status == "ok"
        && r_rec
            .payload
            .get("body")
            .and_then(|b| b.get("authorization"))
            .and_then(Value::as_str)
            != Some("quorum");

    if r_rec.kind_path().as_deref() != Some(KIND_ROOTS_CHANGED)
        || !r_on_valid_nonforked_start
        || r_body_status == "failed"
        || r_auth_not_quorum
    {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approval_not_for_quorum_change",
                Some(change_ref.to_string()),
            ),
            None,
        );
    }

    // Row A6: `R`'s `body` is `incomplete`.
    if r_body_status != "ok" {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "incomplete",
                "unverified_start_record",
                Some(change_ref.to_string()),
            ),
            None,
        );
    }

    let r_stream_str = r_stream.expect("validated above");
    let r_seq = r_seq_opt.expect("validated above");
    let r_replaces = r_rec
        .payload
        .get("body")
        .and_then(|b| b.get("replaces"))
        .and_then(Value::as_str)
        .expect("R.body is ok");
    let r_captured_at = r_rec
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false))
        .expect("R.body is ok");

    // Row A7: At `(R.stream, R.seq - 1)`, no opened record `P` exists.
    let by_seq = by_stream_seq.get(r_stream_str).expect("validated above");
    let Some(prev_indices) = by_seq.get(&(r_seq - 1)).filter(|v| !v.is_empty()) else {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "incomplete",
                "prior_start_not_carried",
                Some(r_replaces.to_string()),
            ),
            None,
        );
    };

    let p_idx = prev_indices
        .iter()
        .copied()
        .find(|&idx| opened_records[idx].rec_ref == r_replaces)
        .unwrap_or(prev_indices[0]);
    let p_rec = &opened_records[p_idx];
    let p_start = start_finding_by_idx
        .get(&p_idx)
        .expect("prior start seq evaluated before approvals at r_seq");

    // Row A8: `P.ref != R.body.replaces` or `P`'s `start` finding is `failed`.
    if p_rec.rec_ref != r_replaces || p_start.result == "failed" {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approval_not_for_quorum_change",
                Some(p_rec.rec_ref.clone()),
            ),
            None,
        );
    }

    // Row A9: `P`'s `start` finding is `incomplete` with a code other than
    // `chain_not_trusted` or `new_roots_not_trusted`.
    if p_start.result == "incomplete"
        && !matches!(
            p_start.code.as_str(),
            "chain_not_trusted" | "new_roots_not_trusted"
        )
    {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "incomplete",
                "unverified_start_record",
                Some(p_rec.rec_ref.clone()),
            ),
            None,
        );
    }

    // Prior terms `T = P.body` (`P`'s `body` is guaranteed `"ok"` after Rows A8 & A9).
    let t_body = p_rec.payload.get("body").expect("P.body is ok");
    let t_roots: BTreeSet<&str> = t_body
        .get("roots")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("key").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let t_recovery_keys: BTreeSet<&str> = t_body
        .get("recoveryKeys")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    // Row A10: `A.body.root` not in `T.roots[*].key`, `A.body.custodianKey` in `T.roots[*].key`
    // or `T.recoveryKeys`, or valid `Principal` declares `holder == "agent"` for either.
    if !t_roots.contains(a_root) || agent_principal_keys.contains(a_root) {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approver_not_in_quorum",
                Some(a_root.to_string()),
            ),
            None,
        );
    }
    if t_roots.contains(a_custodian_key)
        || t_recovery_keys.contains(a_custodian_key)
        || agent_principal_keys.contains(a_custodian_key)
    {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approver_not_in_quorum",
                Some(a_custodian_key.to_string()),
            ),
            None,
        );
    }

    // Row A11: `T.custodians` absent or no entry has `identity == A.body.custodian`.
    let c_entry_opt = t_body
        .get("custodians")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|entry| entry.get("identity").and_then(Value::as_str) == Some(a_custodian))
        });
    let Some(c_entry) = c_entry_opt else {
        return (
            Finding::new(
                2,
                &a_rec.rec_ref,
                "start",
                "failed",
                "approver_not_in_quorum",
                Some(a_custodian.to_string()),
            ),
            None,
        );
    };

    // Row A12: `C_entry` has `key` present, and `A.body.custodianKey != C_entry.key`.
    if let Some(bound_key) = c_entry.get("key").and_then(Value::as_str) {
        if a_custodian_key != bound_key {
            return (
                Finding::new(
                    2,
                    &a_rec.rec_ref,
                    "start",
                    "failed",
                    "custodian_key_not_bound",
                    Some(a_custodian_key.to_string()),
                ),
                None,
            );
        }
    } else {
        // Rows A13 & A14: late-bound custodian key (`C_entry` omits `key`).
        let prior_roots_owned: BTreeSet<String> = t_roots.iter().map(|&k| k.to_string()).collect();
        let shown_times = authority::compute_qualifying_shown_times_for_roots(
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            seal_covered_records,
            &prior_roots_owned,
        );

        // Collect refs revoked at or before `R.capturedAt` by an entitled root in `T.roots[*].key`.
        let mut revoked_by_root_by_r: BTreeSet<&str> = BTreeSet::new();
        for (v_idx, v_rec) in opened_records.iter().enumerate() {
            if v_rec.kind_path().as_deref() != Some(KIND_REVOCATION)
                || body_result_by_idx[v_idx] != "ok"
                || !v_rec.all_sigs_ok
            {
                continue;
            }
            if !t_roots.contains(v_rec.signers[0].as_str()) {
                continue;
            }
            let Some(v_cap) = v_rec
                .payload
                .get("capturedAt")
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339_instant(s, None, false))
            else {
                continue;
            };
            if v_cap <= r_captured_at
                && let Some(tgt) = v_rec
                    .payload
                    .get("body")
                    .and_then(|b| b.get("target"))
                    .and_then(Value::as_str)
            {
                revoked_by_root_by_r.insert(tgt);
            }
        }

        let mut any_sealed_before_r = false;
        let mut min_unsealed_pre_r_ref: Option<&str> = None;

        for (e_idx, e_rec) in opened_records.iter().enumerate() {
            if e_rec.kind_path().as_deref() != Some(KIND_ENDORSEMENT)
                || body_result_by_idx[e_idx] != "ok"
                || !e_rec.all_sigs_ok
            {
                continue;
            }
            let e_issuer = e_rec.signers[0].as_str();
            if !t_roots.contains(e_issuer) || e_issuer == a_custodian_key {
                continue;
            }
            if revoked_by_root_by_r.contains(e_rec.rec_ref.as_str()) {
                continue;
            }
            let Some(e_body) = e_rec.payload.get("body") else {
                continue;
            };
            if e_body.get("parent").is_some() {
                continue;
            }
            if e_body.get("subject").and_then(Value::as_str) != Some(a_custodian_key) {
                continue;
            }
            if e_body.get("actsFor").and_then(Value::as_str) != Some(a_custodian) {
                continue;
            }
            let has_approval_kind =
                e_body
                    .get("kinds")
                    .and_then(Value::as_array)
                    .is_some_and(|arr| {
                        arr.iter()
                            .any(|v| v.as_str() == Some(KIND_ROOT_CHANGE_APPROVAL))
                    });
            if !has_approval_kind {
                continue;
            }
            let (Some(e_cap), Some(nb), Some(na)) = (
                e_rec
                    .payload
                    .get("capturedAt")
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false)),
                e_body
                    .get("notBefore")
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false)),
                e_body
                    .get("notAfter")
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false)),
            ) else {
                continue;
            };
            if a_cap < nb || a_cap > na {
                continue;
            }

            let sealed_before_r = shown_times
                .get(&e_rec.rec_ref)
                .is_some_and(|seals| seals.iter().any(|s| s < &r_captured_at));
            if sealed_before_r {
                any_sealed_before_r = true;
                break;
            }
            if e_cap < r_captured_at
                && min_unsealed_pre_r_ref
                    .is_none_or(|cur| e_rec.rec_ref.as_bytes() < cur.as_bytes())
            {
                min_unsealed_pre_r_ref = Some(e_rec.rec_ref.as_str());
            }
        }

        if !any_sealed_before_r {
            if let Some(e_ref) = min_unsealed_pre_r_ref {
                // Row A14
                return (
                    Finding::new(
                        2,
                        &a_rec.rec_ref,
                        "start",
                        "incomplete",
                        "custodian_key_not_sealed_before_change",
                        Some(e_ref.to_string()),
                    ),
                    None,
                );
            }
            // Row A13
            return (
                Finding::new(
                    2,
                    &a_rec.rec_ref,
                    "start",
                    "failed",
                    "custodian_key_not_bound",
                    Some(a_custodian_key.to_string()),
                ),
                None,
            );
        }
    }

    // Row A15: `ok`.
    (
        Finding::new(
            2,
            &a_rec.rec_ref,
            "start",
            "ok",
            "ok",
            Some(change_ref.to_string()),
        ),
        Some((
            change_ref.to_string(),
            OkApprovalInfo {
                root: a_root.to_string(),
                custodian: a_custodian.to_string(),
                custodian_key: a_custodian_key.to_string(),
            },
        )),
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_record_on_start_stream(
    rec_idx: usize,
    stream: &str,
    seq: i64,
    rec_indices_at_pos: &[usize],
    by_seq: &BTreeMap<i64, Vec<usize>>,
    candidate_streams: &BTreeSet<String>,
    opened_records: &[OpenedRecord],
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    start_finding_by_idx: &BTreeMap<usize, Finding>,
    spent_recovery_keys: &mut BTreeSet<String>,
    ok_approvals_for_rec: &[OkApprovalInfo],
    opts: &VerifyOptions,
) -> Finding {
    let rec = &opened_records[rec_idx];

    // Row 1: More than one distinct candidate start stream exists in the bundle.
    if candidate_streams.len() > 1 {
        let other = candidate_streams
            .iter()
            .find(|s| s.as_str() != stream)
            .expect("at least two distinct candidate start streams")
            .clone();
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "multiple_start_streams",
            Some(other),
        );
    }

    // Row 2: `R`'s kind path is not in `START_STREAM_KINDS`.
    let kind_path = rec.kind_path();
    if !kind_path
        .as_deref()
        .is_some_and(|kp| START_STREAM_KINDS.contains(&kp))
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "not_a_start_record",
            kind_path,
        );
    }
    let kp = kind_path.as_deref().unwrap();

    // Row 3: `R.stream` does not match `^urn:r5e:stream:[a-z0-9][a-z0-9-]*:start$`,
    // or (`R` is `ChainStarted` and `R.seq != 1`),
    // or (`R` is `Deployment` and `R.seq != 2`),
    // or (`R` is `RootsChanged` and `R.seq < 3`).
    let valid_pos = match kp {
        KIND_CHAIN_STARTED => seq == 1,
        KIND_DEPLOYMENT => seq == 2,
        KIND_ROOTS_CHANGED => seq >= 3,
        _ => false,
    };
    if !is_valid_start_stream_uri(stream) || !valid_pos {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "wrong_start_position",
            Some(format!("seq:{seq}")),
        );
    }

    // Row 4: Two or more opened records share `(R.stream, R.seq)`.
    if rec_indices_at_pos.len() >= 2 {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "forked_start_stream",
            Some(format!("seq:{seq}")),
        );
    }

    // Row 5: `R`'s `body` finding is `failed` or any `signature` finding of `R` is `failed`.
    if body_result_by_idx[rec_idx] == "failed" || any_sig_failed_by_idx[rec_idx] {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "invalid_start_record",
            None,
        );
    }

    // Row 6: `R`'s `body` finding is `incomplete` or any `signature` finding of `R` is `incomplete`.
    if body_result_by_idx[rec_idx] != "ok" || !rec.all_sigs_ok {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "incomplete",
            "unverified_start_record",
            None,
        );
    }

    let Some(body) = rec.payload.get("body") else {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "invalid_start_record",
            None,
        );
    };

    if kp == KIND_CHAIN_STARTED {
        let (Some(deployment), Some(bootstrap), Some(defs)) = (
            body.get("deployment").and_then(Value::as_str),
            body.get("bootstrap").and_then(Value::as_str),
            body.get("definitions").and_then(Value::as_array),
        ) else {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "invalid_start_record",
                None,
            );
        };

        // Row 7 (`ChainStarted`): `R.stream != "urn:r5e:stream:" + R.body.deployment + ":start"`.
        let expected_stream = format!("urn:r5e:stream:{deployment}:start");
        if stream != expected_stream {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "deployment_stream_mismatch",
                Some(stream.to_string()),
            );
        }

        // Row 8 (`ChainStarted`): `R.body.definitions` lists any `kind` more than once.
        let mut seen_kinds: BTreeSet<&str> = BTreeSet::new();
        for entry in defs {
            let Some(k) = entry.get("kind").and_then(Value::as_str) else {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "start",
                    "failed",
                    "invalid_start_record",
                    None,
                );
            };
            if !seen_kinds.insert(k) {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "start",
                    "failed",
                    "invalid_start_record",
                    None,
                );
            }
        }

        // Row 9 (`ChainStarted`): No opened record exists at `(R.stream, seq = 2)`.
        if by_seq.get(&2).is_none_or(Vec::is_empty) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "incomplete",
                "deployment_not_carried",
                None,
            );
        }

        // Row 10 (`ChainStarted`): Otherwise `ok`.
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "ok",
            "ok",
            Some(bootstrap.to_string()),
        );
    }

    if kp == KIND_DEPLOYMENT {
        let (Some(accepts), Some(bootstrap), Some(claimed_by), Some(roots), Some(threshold)) = (
            body.get("accepts").and_then(Value::as_str),
            body.get("bootstrap").and_then(Value::as_str),
            body.get("claimedBy").and_then(Value::as_str),
            body.get("roots").and_then(Value::as_array),
            body.get("threshold").and_then(parse_v2_integer),
        ) else {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "invalid_start_record",
                None,
            );
        };

        if roots
            .iter()
            .any(|r| r.get("key").and_then(Value::as_str).is_none())
        {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "invalid_start_record",
                None,
            );
        }

        // Row 11 (`Deployment`): Tightened deployment terms (§3.2).
        if !terms_hold(body, roots, threshold, Some(claimed_by)) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "invalid_deployment_terms",
                None,
            );
        }

        // Row 12 (`Deployment`): `R.previous != R.body.accepts`.
        let r_prev = rec.payload.get("previous").and_then(Value::as_str);
        if r_prev != Some(accepts) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "accepts_is_not_chain_started",
                Some(accepts.to_string()),
            );
        }

        // Row 13 (`Deployment`): No opened record `C` exists at `(R.stream, seq = 1)`.
        let Some(seq1_indices) = by_seq.get(&1).filter(|v| !v.is_empty()) else {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "incomplete",
                "chain_started_not_carried",
                Some(accepts.to_string()),
            );
        };

        let c_idx = seq1_indices
            .iter()
            .copied()
            .find(|&idx| opened_records[idx].rec_ref == accepts)
            .unwrap_or(seq1_indices[0]);
        let c_rec = &opened_records[c_idx];
        let c_start = start_finding_by_idx
            .get(&c_idx)
            .expect("seq = 1 evaluated before seq = 2");

        // Row 14 (`Deployment`): `C.ref != R.body.accepts` or `C`'s `start` finding is `failed`.
        if c_rec.rec_ref != accepts || c_start.result == "failed" {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "accepts_is_not_chain_started",
                Some(c_rec.rec_ref.clone()),
            );
        }

        // Row 15 (`Deployment`): `C`'s `body` is `ok` and `R.body.bootstrap != C.body.bootstrap`.
        if body_result_by_idx[c_idx] == "ok" {
            let c_bootstrap = c_rec
                .payload
                .get("body")
                .and_then(|b| b.get("bootstrap"))
                .and_then(Value::as_str);
            if c_bootstrap != Some(bootstrap) {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "start",
                    "failed",
                    "bootstrap_signer_mismatch",
                    c_bootstrap.map(str::to_string),
                );
            }
        }

        // Row 16 (`Deployment`): `C`'s `start` finding is `incomplete`.
        if c_start.result == "incomplete" {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "incomplete",
                "unverified_start_record",
                Some(c_rec.rec_ref.clone()),
            );
        }

        // Row 17 (`Deployment`): `trustedChain != null` and `R.ref != trustedChain`.
        if let Some(tc) = opts.trusted_chain.as_deref()
            && rec.rec_ref != tc
        {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "chain_mismatch",
                Some(tc.to_string()),
            );
        }

        // Row 18 (`Deployment`): Neither (`trustedChain == R.ref`) nor
        // (`trustedRoots` is a list and `R.body.claimedBy` is in `trustedRoots`).
        let trusted_by_chain = opts.trusted_chain.as_deref() == Some(rec.rec_ref.as_str());
        let trusted_by_root = opts
            .trusted_roots
            .as_ref()
            .is_some_and(|roots| roots.contains(claimed_by));
        if !trusted_by_chain && !trusted_by_root {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "incomplete",
                "chain_not_trusted",
                Some(rec.rec_ref.clone()),
            );
        }

        // Row 19 (`Deployment`): Otherwise `ok`.
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "ok",
            "ok",
            Some(c_rec.rec_ref.clone()),
        );
    }

    // `RootsChanged` (`seq >= 3`, Rows 20–35, `A6` Slice 2 §3.4):
    let (
        Some(chain),
        Some(replaces),
        Some(authorization),
        Some(signer),
        Some(roots),
        Some(threshold),
        Some(r_captured_at),
    ) = (
        body.get("chain").and_then(Value::as_str),
        body.get("replaces").and_then(Value::as_str),
        body.get("authorization").and_then(Value::as_str),
        body.get("signer").and_then(Value::as_str),
        body.get("roots").and_then(Value::as_array),
        body.get("threshold").and_then(parse_v2_integer),
        rec.payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false)),
    )
    else {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "invalid_start_record",
            None,
        );
    };

    if authorization == "recovery" {
        spent_recovery_keys.insert(signer.to_string());
    }

    // Row 20 (`RootsChanged`): `R.body` violates §3.2 terms rules.
    if !terms_hold(body, roots, threshold, None) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "invalid_deployment_terms",
            None,
        );
    }

    // Row 21 (`RootsChanged`): `R.previous != R.body.replaces`.
    let r_prev = rec.payload.get("previous").and_then(Value::as_str);
    if r_prev != Some(replaces) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "replaces_is_not_prior_start",
            Some(replaces.to_string()),
        );
    }

    // Row 22 (`RootsChanged`): No opened record `P` exists at `(R.stream, seq = n - 1)`.
    let Some(prev_indices) = by_seq.get(&(seq - 1)).filter(|v| !v.is_empty()) else {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "incomplete",
            "prior_start_not_carried",
            Some(replaces.to_string()),
        );
    };

    let p_idx = prev_indices
        .iter()
        .copied()
        .find(|&idx| opened_records[idx].rec_ref == replaces)
        .unwrap_or(prev_indices[0]);
    let p_rec = &opened_records[p_idx];
    let p_start = start_finding_by_idx
        .get(&p_idx)
        .expect("prior start seq evaluated before seq");

    // Row 23 (`RootsChanged`): `P.ref != R.body.replaces` or `P`'s `start` finding is `failed`.
    if p_rec.rec_ref != replaces || p_start.result == "failed" {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "replaces_is_not_prior_start",
            Some(p_rec.rec_ref.clone()),
        );
    }

    // Row 24 (`RootsChanged`): `P`'s `body` is `ok` and `R.body.chain != D_ref`.
    if body_result_by_idx[p_idx] == "ok" {
        let d_ref = if seq == 3 {
            Some(p_rec.rec_ref.as_str())
        } else {
            p_rec
                .payload
                .get("body")
                .and_then(|b| b.get("chain"))
                .and_then(Value::as_str)
        };
        if d_ref != Some(chain) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "start_chain_mismatch",
                d_ref.map(str::to_string),
            );
        }

        // Row 25 (`RootsChanged`): `instant(R.capturedAt) < instant(P.capturedAt)`.
        if let Some(p_cap) = p_rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
            && r_captured_at < p_cap
        {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "start_timestamp_regression",
                Some(p_rec.rec_ref.clone()),
            );
        }
    }

    // Row 26 (`RootsChanged`): `P`'s `start` finding is `incomplete` with a code other than
    // `chain_not_trusted` or `new_roots_not_trusted`.
    if p_start.result == "incomplete"
        && !matches!(
            p_start.code.as_str(),
            "chain_not_trusted" | "new_roots_not_trusted"
        )
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "incomplete",
            "unverified_start_record",
            Some(p_rec.rec_ref.clone()),
        );
    }

    let p_body = p_rec
        .payload
        .get("body")
        .expect("P.body is ok after Rows 23 & 26");
    let p_roots: BTreeSet<&str> = p_body
        .get("roots")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("key").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let p_recovery_keys: BTreeSet<&str> = p_body
        .get("recoveryKeys")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let p_threshold = p_body
        .get("threshold")
        .and_then(parse_v2_integer)
        .expect("P.body is ok");

    // Row 27 (`recovery`): `R.body.authorization == "recovery"` and `R.body.signer` not in `P.body.recoveryKeys`.
    if authorization == "recovery" && !p_recovery_keys.contains(signer) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "unauthorized_recovery_signer",
            Some(signer.to_string()),
        );
    }

    // Row 28: `R.body.recoveryKeys` overlaps `spent_at_n`.
    if let Some(r_rk_arr) = body.get("recoveryKeys").and_then(Value::as_array) {
        let mut min_spent: Option<&str> = None;
        for item in r_rk_arr {
            if let Some(rk) = item.as_str()
                && spent_recovery_keys.contains(rk)
                && min_spent.is_none_or(|cur| rk.as_bytes() < cur.as_bytes())
            {
                min_spent = Some(rk);
            }
        }
        if let Some(spent_rk) = min_spent {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "spent_recovery_key_retained",
                Some(spent_rk.to_string()),
            );
        }
    }

    if authorization == "quorum" {
        // Row 29 (`quorum`): `R.body.signer` not in `P.body.roots[*].key`.
        if !p_roots.contains(signer) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "proposer_not_a_root",
                Some(signer.to_string()),
            );
        }

        // Row 30 (`quorum`): `P.body.custodians` absent or `len(P.body.custodians) < P.body.threshold`.
        let cust_len = p_body
            .get("custodians")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if (cust_len as i64) < p_threshold {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "failed",
                "quorum_not_configured",
                None,
            );
        }

        // Row 31 (`quorum`): `quorum_count < P.body.threshold`.
        let quorum_count = count_veto_free_quorum(ok_approvals_for_rec);
        if (quorum_count as i64) < p_threshold {
            return Finding::new(
                2,
                &rec.rec_ref,
                "start",
                "incomplete",
                "quorum_not_carried",
                Some(format!("need:{p_threshold}")),
            );
        }
    }

    // Row 32: `trustedChain != null` and `R.body.chain != trustedChain`.
    if let Some(tc) = opts.trusted_chain.as_deref()
        && chain != tc
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "chain_mismatch",
            Some(tc.to_string()),
        );
    }

    // Row 33: `trustedChain == null` and `trustedRoots` is a list and some key in
    // `R.body.roots[*].key` is not in `trustedRoots`.
    let r_root_keys: BTreeSet<&str> = roots
        .iter()
        .filter_map(|v| v.get("key").and_then(Value::as_str))
        .collect();
    if opts.trusted_chain.is_none()
        && let Some(tr) = &opts.trusted_roots
        && let Some(&untrusted_k) = r_root_keys.iter().find(|&&k| !tr.contains(k))
    {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "incomplete",
            "new_roots_not_trusted",
            Some(untrusted_k.to_string()),
        );
    }

    // Row 34: `trustedChain == null` and `trustedRoots == null`.
    if opts.trusted_chain.is_none() && opts.trusted_roots.is_none() {
        return Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "incomplete",
            "chain_not_trusted",
            Some(chain.to_string()),
        );
    }

    // Row 35: Otherwise `ok`.
    Finding::new(
        2,
        &rec.rec_ref,
        "start",
        "ok",
        "ok",
        Some(p_rec.rec_ref.clone()),
    )
}

fn extract_record_roots_and_time(rec: &OpenedRecord) -> Option<(BTreeSet<String>, UtcInstant)> {
    let cap_str = rec.payload.get("capturedAt")?.as_str()?;
    let cap = parse_rfc3339_instant(cap_str, None, false)?;
    let roots_arr = rec.payload.get("body")?.get("roots")?.as_array()?;
    let mut keys = BTreeSet::new();
    for item in roots_arr {
        keys.insert(item.get("key")?.as_str()?.to_string());
    }
    Some((keys, cap))
}

/// Builds root tenures `(key, admitted_at, ended_by)` across a contiguous prefix `S_2 .. S_m`
/// (`A6` Slice 2 §4.2.2). When `pinned_filter` is `Some(tr)`, only keys in `tr` receive tenures.
fn build_tenures_from_start_records(
    seq_indices: &[usize],
    opened_records: &[OpenedRecord],
    pinned_filter: Option<&BTreeSet<String>>,
) -> Vec<RootTenure> {
    let mut tenures: Vec<RootTenure> = Vec::new();
    let mut open_idx_by_key: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_pinned: BTreeSet<String> = BTreeSet::new();

    for (pos_offset, &rec_idx) in seq_indices.iter().enumerate() {
        let rec = &opened_records[rec_idx];
        let Some((roots_at_pos, cap_at_pos)) = extract_record_roots_and_time(rec) else {
            break;
        };

        if pos_offset == 0 {
            for k in roots_at_pos {
                if pinned_filter.is_some_and(|tr| !tr.contains(&k)) {
                    continue;
                }
                seen_pinned.insert(k.clone());
                let idx = tenures.len();
                tenures.push(RootTenure {
                    key: k.clone(),
                    admitted_at: Some(cap_at_pos.clone()),
                    ended_by: None,
                });
                open_idx_by_key.insert(k, idx);
            }
        } else {
            // Close open tenures removed at `S_i`.
            let currently_open: Vec<(String, usize)> = open_idx_by_key
                .iter()
                .map(|(k, &i)| (k.clone(), i))
                .collect();
            for (k, t_idx) in currently_open {
                if !roots_at_pos.contains(&k) {
                    tenures[t_idx].ended_by = Some((rec.rec_ref.clone(), cap_at_pos.clone()));
                    open_idx_by_key.remove(&k);
                }
            }
            // Open tenures for newly admitted keys at `S_i`.
            for k in roots_at_pos {
                if pinned_filter.is_some_and(|tr| !tr.contains(&k)) {
                    continue;
                }
                seen_pinned.insert(k.clone());
                if let std::collections::btree_map::Entry::Vacant(e) = open_idx_by_key.entry(k) {
                    let idx = tenures.len();
                    tenures.push(RootTenure {
                        key: e.key().clone(),
                        admitted_at: Some(cap_at_pos.clone()),
                        ended_by: None,
                    });
                    e.insert(idx);
                }
            }
        }
    }

    if let Some(tr) = pinned_filter {
        for k in tr {
            if !seen_pinned.contains(k) {
                tenures.push(RootTenure {
                    key: k.clone(),
                    admitted_at: None,
                    ended_by: None,
                });
            }
        }
    }

    tenures
}

/// Evaluates Layer 2 `start` findings (`A6` Slice 1 & Slice 2), builds the optional top-level
/// `"start"` report member, and constructs root tenures for `A5` (`trustedChain` or `trustedRoots`).
pub(crate) fn evaluate_start(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    opts: &VerifyOptions,
) -> StartEvaluation {
    let mut candidate_streams: BTreeSet<String> = BTreeSet::new();
    let mut streamless_start_records: Vec<usize> = Vec::new();
    let mut stream_record_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut agent_principal_keys: BTreeSet<&str> = BTreeSet::new();

    for (idx, rec) in opened_records.iter().enumerate() {
        let kp = rec.kind_path();
        let is_start_kind = kp
            .as_deref()
            .is_some_and(|k| START_STREAM_KINDS.contains(&k));

        if kp.as_deref() == Some(KIND_PRINCIPAL)
            && body_result_by_idx[idx] == "ok"
            && rec.all_sigs_ok
            && let Some(b) = rec.payload.get("body")
            && b.get("holder").and_then(Value::as_str) == Some("agent")
            && let Some(key_id) = b.get("key").and_then(Value::as_str)
        {
            agent_principal_keys.insert(key_id);
        }

        match rec.payload.get("stream").and_then(Value::as_str) {
            Some(s) => {
                *stream_record_counts.entry(s).or_insert(0) += 1;
                if is_candidate_start_stream_uri(s) || is_start_kind {
                    candidate_streams.insert(s.to_string());
                }
            }
            None => {
                if is_start_kind {
                    streamless_start_records.push(idx);
                }
            }
        }
    }

    let mut off_stream_approvals: Vec<usize> = Vec::new();
    let mut approvals_by_change_ref: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, rec) in opened_records.iter().enumerate() {
        if rec.kind_path().as_deref() != Some(KIND_ROOT_CHANGE_APPROVAL) {
            continue;
        }
        let on_candidate_stream = rec
            .payload
            .get("stream")
            .and_then(Value::as_str)
            .is_some_and(|s| candidate_streams.contains(s));
        if on_candidate_stream {
            continue;
        }
        off_stream_approvals.push(idx);
        if let Some(ch) = rec
            .payload
            .get("body")
            .and_then(|b| b.get("change"))
            .and_then(Value::as_str)
        {
            approvals_by_change_ref.entry(ch).or_default().push(idx);
        }
    }

    let mut by_stream_seq: BTreeMap<String, BTreeMap<i64, Vec<usize>>> = BTreeMap::new();
    let mut malformed_seq_by_stream: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for (idx, rec) in opened_records.iter().enumerate() {
        let Some(stream) = rec.payload.get("stream").and_then(Value::as_str) else {
            continue;
        };
        if !candidate_streams.contains(stream) {
            continue;
        }
        match rec.payload.get("seq").and_then(parse_v2_integer) {
            Some(seq) => {
                by_stream_seq
                    .entry(stream.to_string())
                    .or_default()
                    .entry(seq)
                    .or_default()
                    .push(idx);
            }
            None => {
                malformed_seq_by_stream
                    .entry(stream.to_string())
                    .or_default()
                    .push(idx);
            }
        }
    }

    for by_seq in by_stream_seq.values_mut() {
        for indices in by_seq.values_mut() {
            indices.sort_by(|&a, &b| {
                opened_records[a]
                    .rec_ref
                    .as_bytes()
                    .cmp(opened_records[b].rec_ref.as_bytes())
            });
        }
    }

    let mut start_finding_by_idx: BTreeMap<usize, Finding> = BTreeMap::new();
    let mut stream_and_pin_findings: Vec<Finding> = Vec::new();
    let mut approval_findings: Vec<Finding> = Vec::new();
    let mut evaluated_approvals: BTreeSet<usize> = BTreeSet::new();
    let mut ok_approvals_by_change: BTreeMap<String, Vec<OkApprovalInfo>> = BTreeMap::new();

    for stream in &candidate_streams {
        let mut spent_recovery_keys: BTreeSet<String> = BTreeSet::new();
        if let Some(by_seq) = by_stream_seq.get(stream) {
            for (&seq, rec_indices) in by_seq {
                // Before evaluating `RootsChanged` at `seq >= 3` on a single candidate stream,
                // evaluate any off-stream `RootChangeApproval`s citing records at `seq`.
                if candidate_streams.len() == 1 && seq >= 3 {
                    for &rec_idx in rec_indices {
                        let rec_ref = opened_records[rec_idx].rec_ref.as_str();
                        if let Some(a_indices) = approvals_by_change_ref.get(rec_ref) {
                            for &a_idx in a_indices {
                                if !evaluated_approvals.insert(a_idx) {
                                    continue;
                                }
                                let (af, ok_info) = evaluate_off_stream_approval(
                                    a_idx,
                                    &stream_record_counts,
                                    &candidate_streams,
                                    &by_stream_seq,
                                    opened_records,
                                    opened_by_ref,
                                    any_sig_failed_by_idx,
                                    body_result_by_idx,
                                    seal_covered_records,
                                    &agent_principal_keys,
                                    &start_finding_by_idx,
                                );
                                if let Some((ch_ref, info)) = ok_info {
                                    ok_approvals_by_change.entry(ch_ref).or_default().push(info);
                                }
                                start_finding_by_idx.insert(a_idx, af.clone());
                                approval_findings.push(af);
                            }
                        }
                    }
                }

                for &rec_idx in rec_indices {
                    let ok_apps = ok_approvals_by_change
                        .get(&opened_records[rec_idx].rec_ref)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    let f = evaluate_record_on_start_stream(
                        rec_idx,
                        stream,
                        seq,
                        rec_indices,
                        by_seq,
                        &candidate_streams,
                        opened_records,
                        any_sig_failed_by_idx,
                        body_result_by_idx,
                        &start_finding_by_idx,
                        &mut spent_recovery_keys,
                        ok_apps,
                        opts,
                    );
                    start_finding_by_idx.insert(rec_idx, f.clone());
                    stream_and_pin_findings.push(f);
                }
            }
        }
        if let Some(bad_indices) = malformed_seq_by_stream.get(stream) {
            for &rec_idx in bad_indices {
                let rec = &opened_records[rec_idx];
                let f = if candidate_streams.len() > 1 {
                    let other = candidate_streams
                        .iter()
                        .find(|s| s.as_str() != stream.as_str())
                        .unwrap()
                        .clone();
                    Finding::new(
                        2,
                        &rec.rec_ref,
                        "start",
                        "failed",
                        "multiple_start_streams",
                        Some(other),
                    )
                } else if !rec
                    .kind_path()
                    .as_deref()
                    .is_some_and(|kp| START_STREAM_KINDS.contains(&kp))
                {
                    Finding::new(
                        2,
                        &rec.rec_ref,
                        "start",
                        "failed",
                        "not_a_start_record",
                        rec.kind_path(),
                    )
                } else {
                    Finding::new(
                        2,
                        &rec.rec_ref,
                        "start",
                        "failed",
                        "invalid_start_record",
                        None,
                    )
                };
                start_finding_by_idx.insert(rec_idx, f.clone());
                stream_and_pin_findings.push(f);
            }
        }
    }

    for rec_idx in streamless_start_records {
        let rec = &opened_records[rec_idx];
        let f = Finding::new(
            2,
            &rec.rec_ref,
            "start",
            "failed",
            "invalid_start_record",
            None,
        );
        start_finding_by_idx.insert(rec_idx, f.clone());
        stream_and_pin_findings.push(f);
    }

    // Evaluate any remaining off-stream `RootChangeApproval` records not yet evaluated.
    for a_idx in off_stream_approvals {
        if !evaluated_approvals.insert(a_idx) {
            continue;
        }
        let (af, _) = evaluate_off_stream_approval(
            a_idx,
            &stream_record_counts,
            &candidate_streams,
            &by_stream_seq,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            seal_covered_records,
            &agent_principal_keys,
            &start_finding_by_idx,
        );
        start_finding_by_idx.insert(a_idx, af.clone());
        approval_findings.push(af);
    }

    // §2.3 Top-level `"start"` report member: included iff a single candidate start stream has
    // position 1 (`ChainStarted`) with `start == ok`.
    let mut report_start: Option<StartSummary> = None;
    let mut ok_start_seq_indices_from_2: Vec<usize> = Vec::new();
    if candidate_streams.len() == 1
        && let Some(stream) = candidate_streams.iter().next()
        && let Some(by_seq) = by_stream_seq.get(stream)
        && let Some(seq1) = by_seq.get(&1)
        && seq1.len() == 1
    {
        let c_idx = seq1[0];
        if start_finding_by_idx
            .get(&c_idx)
            .is_some_and(|f| f.result == "ok")
        {
            let c_rec = &opened_records[c_idx];
            let deployment = c_rec
                .payload
                .get("body")
                .and_then(|b| b.get("deployment"))
                .and_then(Value::as_str)
                .expect("ChainStarted with start == ok has deployment")
                .to_string();
            let mut head_seq: i64 = 1;
            let mut head_ref = c_rec.rec_ref.clone();
            let mut head_captured_at = c_rec
                .payload
                .get("capturedAt")
                .and_then(Value::as_str)
                .expect("ChainStarted with start == ok has capturedAt")
                .to_string();
            let mut chain: Option<String> = None;

            let mut next_seq: i64 = 2;
            while let Some(indices) = by_seq.get(&next_seq) {
                if indices.len() != 1 {
                    break;
                }
                let r_idx = indices[0];
                if start_finding_by_idx
                    .get(&r_idx)
                    .is_none_or(|f| f.result != "ok")
                {
                    break;
                }
                let r_rec = &opened_records[r_idx];
                let Some(cap) = r_rec.payload.get("capturedAt").and_then(Value::as_str) else {
                    break;
                };
                head_seq = next_seq;
                head_ref = r_rec.rec_ref.clone();
                head_captured_at = cap.to_string();
                if next_seq == 2 {
                    chain = Some(r_rec.rec_ref.clone());
                }
                ok_start_seq_indices_from_2.push(r_idx);
                next_seq += 1;
            }

            report_start = Some(StartSummary {
                chain,
                deployment,
                head_captured_at,
                head_ref,
                head_seq,
                stream: stream.clone(),
            });
        }
    }

    // §4.3 Reader-pin completeness findings:
    // 1. Missing `trustedChain`.
    if let Some(tc) = opts.trusted_chain.as_deref() {
        let has_matching_deployment = opened_records
            .iter()
            .any(|r| r.rec_ref == tc && r.kind_path().as_deref() == Some(KIND_DEPLOYMENT));
        let already_emitted_mismatch_or_multi = stream_and_pin_findings
            .iter()
            .any(|f| f.code == "chain_mismatch" || f.code == "multiple_start_streams");
        if !has_matching_deployment && !already_emitted_mismatch_or_multi {
            stream_and_pin_findings.push(Finding::new(
                2,
                tc,
                "start",
                "incomplete",
                "chain_start_not_carried",
                None,
            ));
        }
    }

    // 2. Below `minStartSeq`.
    if let Some(min_seq) = opts.min_start_seq {
        let any_stream_failed = stream_and_pin_findings.iter().any(|f| f.result == "failed");
        let meets_min_seq = report_start
            .as_ref()
            .is_some_and(|s| u64::try_from(s.head_seq).is_ok_and(|hs| hs >= min_seq));
        if !any_stream_failed && !meets_min_seq {
            let subj = candidate_streams
                .iter()
                .next()
                .map(String::as_str)
                .unwrap_or("bundle");
            stream_and_pin_findings.push(Finding::new(
                2,
                subj,
                "start",
                "incomplete",
                "start_below_minimum_position",
                Some(format!("seq:{min_seq}")),
            ));
        }
    }

    // §4.2.1 & §4.2.2 Root tenures under `trustedChain`.
    let any_stream_failed = stream_and_pin_findings.iter().any(|f| f.result == "failed");
    let any_stream_incomplete = stream_and_pin_findings
        .iter()
        .any(|f| f.result == "incomplete");

    let pinned_outcome = match opts.trusted_chain.as_deref() {
        None => PinnedChainOutcome::NotPinned,
        Some(tc) => {
            if any_stream_failed {
                PinnedChainOutcome::Failed
            } else if any_stream_incomplete {
                PinnedChainOutcome::Incomplete
            } else if report_start.as_ref().and_then(|s| s.chain.as_deref()) == Some(tc)
                && !ok_start_seq_indices_from_2.is_empty()
            {
                let tenures = build_tenures_from_start_records(
                    &ok_start_seq_indices_from_2,
                    opened_records,
                    None,
                );
                PinnedChainOutcome::Established(tenures)
            } else {
                PinnedChainOutcome::Incomplete
            }
        }
    };

    // §4.2.2 Root tenures under `trustedRoots`.
    let trusted_roots_tenures = match &opts.trusted_roots {
        None => Vec::new(),
        Some(pinned_roots) => {
            if !any_stream_failed
                && candidate_streams.len() == 1
                && let Some(stream) = candidate_streams.iter().next()
                && let Some(by_seq) = by_stream_seq.get(stream)
                && let Some(seq1) = by_seq.get(&1)
                && seq1.len() == 1
                && start_finding_by_idx
                    .get(&seq1[0])
                    .is_some_and(|f| f.result == "ok")
                && let Some(seq2) = by_seq.get(&2)
                && seq2.len() == 1
                && start_finding_by_idx
                    .get(&seq2[0])
                    .is_some_and(|f| f.result == "ok")
            {
                let mut valid_seq_indices = vec![seq2[0]];
                let mut next_seq: i64 = 3;
                while let Some(indices) = by_seq.get(&next_seq) {
                    if indices.len() != 1 {
                        break;
                    }
                    let r_idx = indices[0];
                    let valid_or_unpinned = start_finding_by_idx
                        .get(&r_idx)
                        .is_some_and(|f| matches!(f.code.as_str(), "ok" | "new_roots_not_trusted"));
                    if !valid_or_unpinned {
                        break;
                    }
                    valid_seq_indices.push(r_idx);
                    next_seq += 1;
                }
                build_tenures_from_start_records(
                    &valid_seq_indices,
                    opened_records,
                    Some(pinned_roots),
                )
            } else {
                pinned_roots
                    .iter()
                    .map(|k| RootTenure {
                        key: k.clone(),
                        admitted_at: None,
                        ended_by: None,
                    })
                    .collect()
            }
        }
    };

    let mut all_start_findings = stream_and_pin_findings;
    all_start_findings.extend(approval_findings);

    StartEvaluation {
        findings: all_start_findings,
        report_start,
        pinned_outcome,
        trusted_roots_tenures,
    }
}
