use super::canonical::{
    is_bytes_ref, parse_canonical_json, parse_rfc3339_instant, parse_v2_integer,
};
use super::wire_schema::{WireSchemaKind, validate_wire_schema};
use super::{BaseDefinitions, Finding, OpenedRecord, VerifyOptions};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const KIND_EPOCH_SEAL: &str = "provenance.r5e.io/v2/EpochSeal";
const KIND_CHECKPOINT: &str = "provenance.r5e.io/v2/Checkpoint";
const KIND_RETENTION_HOLD: &str = "provenance.r5e.io/v2/RetentionHold";
const KIND_RETENTION_HOLD_RELEASE: &str = "provenance.r5e.io/v2/RetentionHoldRelease";
const KIND_PAYLOAD_DISPOSITION: &str = "provenance.r5e.io/v2/PayloadDisposition";

fn is_valid_deployment_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !matches!(first, b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    bytes
        .iter()
        .all(|&b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// `A7` §4.1: If `stream` matches `^urn:r5e:stream:([a-z0-9][a-z0-9-]*):.+$` with slug `<d>`,
/// returns `Some("urn:r5e:stream:<d>:retention")`, else `None`.
pub(crate) fn retention_stream_of(stream: &str) -> Option<String> {
    let rest = stream.strip_prefix("urn:r5e:stream:")?;
    let (slug, suffix) = rest.split_once(':')?;
    if !is_valid_deployment_slug(slug) || suffix.is_empty() || suffix.contains('\n') {
        return None;
    }
    Some(format!("urn:r5e:stream:{slug}:retention"))
}

/// `A7` §4.1 & §4.2: Checks `^urn:r5e:stream:[a-z0-9][a-z0-9-]*:retention$`.
pub(crate) fn is_retention_stream_uri(stream: &str) -> bool {
    let Some(rest) = stream.strip_prefix("urn:r5e:stream:") else {
        return false;
    };
    let Some(slug) = rest.strip_suffix(":retention") else {
        return false;
    };
    is_valid_deployment_slug(slug)
}

/// `A7` §4.3: Content scope of an opened record `R`.
pub(crate) fn content_scope_of(rec: &OpenedRecord) -> Option<String> {
    let kp = rec.kind_path();
    if matches!(
        kp.as_deref(),
        Some(
            KIND_EPOCH_SEAL
                | KIND_CHECKPOINT
                | KIND_RETENTION_HOLD
                | KIND_RETENTION_HOLD_RELEASE
                | KIND_PAYLOAD_DISPOSITION
        )
    ) {
        return None;
    }
    let obj = rec.payload.as_object()?;
    if let Some(sess_val) = obj.get("session") {
        sess_val.as_str().map(str::to_string)
    } else {
        obj.get("stream")
            .and_then(Value::as_str)
            .map(|st| format!("stream:{st}"))
    }
}

fn collect_bytes_refs(val: &Value, out: &mut BTreeSet<String>) {
    match val {
        Value::String(s) => {
            if is_bytes_ref(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_bytes_refs(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_bytes_refs(v, out);
            }
        }
        _ => {}
    }
}

const KIND_RELEASE_RECEIPT: &str = "provenance.r5e.io/v2/ReleaseReceipt";

/// `A7` §4.4: Collects distinct `bytes:sha256:<64 hex>` references anywhere in `R.body`,
/// excluding `R.body.targets` when `R` is `RetentionHold` or `PayloadDisposition`,
/// and excluding `releasedFingerprint` / `witnessReceiptRef` on `ReleaseReceipt`.
fn collect_record_content_refs(rec: &OpenedRecord) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(body_val) = rec.payload.get("body") else {
        return out;
    };
    let kp = rec.kind_path();
    let exclude_targets = matches!(
        kp.as_deref(),
        Some(KIND_RETENTION_HOLD | KIND_PAYLOAD_DISPOSITION)
    );
    let exclude_release_receipt_fields = kp.as_deref() == Some(KIND_RELEASE_RECEIPT);
    if exclude_targets || exclude_release_receipt_fields {
        if let Some(map) = body_val.as_object() {
            for (k, v) in map {
                if exclude_targets && k == "targets" {
                    continue;
                }
                if exclude_release_receipt_fields
                    && (k == "releasedFingerprint" || k == "witnessReceiptRef")
                {
                    continue;
                }
                collect_bytes_refs(v, &mut out);
            }
        } else {
            collect_bytes_refs(body_val, &mut out);
        }
    } else {
        collect_bytes_refs(body_val, &mut out);
    }
    out
}

#[derive(Debug, Clone)]
enum TargetOrScope {
    Targets(BTreeSet<String>),
    Scope(String),
}

impl TargetOrScope {
    fn from_body(body: &Value) -> Option<Self> {
        if let Some(targets_arr) = body.get("targets").and_then(Value::as_array) {
            let set = targets_arr
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            Some(Self::Targets(set))
        } else {
            body.get("scope")
                .and_then(Value::as_str)
                .map(|s| Self::Scope(s.to_string()))
        }
    }

    fn matches(&self, rec_ref: &str, rec_scope: Option<&str>, bref: &str) -> bool {
        match self {
            Self::Targets(tset) => tset.contains(bref) || tset.contains(rec_ref),
            Self::Scope(sc) => rec_scope == Some(sc.as_str()),
        }
    }
}

#[derive(Debug)]
struct CountingHold {
    rec_ref: String,
    stream: String,
    seq: i64,
    until_ns: Option<i128>,
    target_or_scope: TargetOrScope,
}

#[derive(Debug)]
struct CountingRelease {
    stream: String,
    seq: i64,
    hold_ref: String,
}

#[derive(Debug)]
struct CountingDisposal {
    rec_ref: String,
    stream: String,
    seq: i64,
    captured_at_ns: i128,
    action_disposes: bool,
    target_or_scope: TargetOrScope,
}

#[derive(Debug, Clone, Copy)]
enum ParsedProfileRetention {
    Never,
    ByRecord { keep_content_for_seconds: i64 },
}

fn parse_capture_profile_retention(bytes: &[u8]) -> Option<ParsedProfileRetention> {
    let val = parse_canonical_json(bytes)?;
    if !val.is_object() || !validate_wire_schema(WireSchemaKind::CaptureProfile, &val) {
        return None;
    }
    let Some(ret_val) = val.get("retention") else {
        return Some(ParsedProfileRetention::Never);
    };
    match ret_val.get("disposal").and_then(Value::as_str)? {
        "never" => Some(ParsedProfileRetention::Never),
        "by-record" => {
            let secs = ret_val
                .get("keepContentForSeconds")
                .and_then(parse_v2_integer)?;
            Some(ParsedProfileRetention::ByRecord {
                keep_content_for_seconds: secs,
            })
        }
        _ => None,
    }
}

/// Evaluates `VERIFY-V2` §6.4 / §6.4a (`A7` §§4–5) `content` findings across all opened records.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_content_findings(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    body_result_by_idx: &[String],
    profile_bounds_ok_by_idx: &[bool],
    authority_ok_by_idx: &[bool],
    base_defs: &BaseDefinitions,
    valid_blobs: &BTreeMap<String, Vec<u8>>,
    omissions_by_ref: &BTreeMap<String, String>,
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    sealer_ok_seal_refs: &BTreeSet<String>,
    a5_qualifying_seal_refs: &BTreeSet<String>,
    opts: &VerifyOptions,
    findings: &mut Vec<Finding>,
) {
    let profile_only_mode = opts.trusted_roots.is_none() && opts.trusted_chain.is_none();

    // 1. Pre-index valid `CaptureProfile` retention policies by `blob_ref`.
    let mut valid_profile_retentions: BTreeMap<String, ParsedProfileRetention> = BTreeMap::new();
    for (blob_ref, raw_bytes) in valid_blobs {
        if let Some(pol) = parse_capture_profile_retention(raw_bytes) {
            valid_profile_retentions.insert(blob_ref.clone(), pol);
        }
    }

    // 2. Pre-index qualifying seals covering each record (`covered_rec_ref -> Vec<(seal_ref, seal_ns)>`).
    let mut qualifying_seals_by_target: BTreeMap<String, Vec<(String, i128)>> = BTreeMap::new();
    for (seal_ref, covered_refs) in seal_covered_records {
        if covered_refs.is_empty() {
            continue;
        }
        let Some(&seal_idx) = opened_by_ref.get(seal_ref) else {
            continue;
        };
        let seal_rec = &opened_records[seal_idx];
        if !seal_rec.all_sigs_ok
            || body_result_by_idx[seal_idx] != "ok"
            || seal_rec.kind_path().as_deref() != Some(KIND_EPOCH_SEAL)
        {
            continue;
        }
        let standing_ok = if profile_only_mode {
            sealer_ok_seal_refs.contains(seal_ref)
                && profile_bounds_ok_by_idx[seal_idx]
                && authority_ok_by_idx[seal_idx]
        } else {
            a5_qualifying_seal_refs.contains(seal_ref)
        };
        if !standing_ok {
            continue;
        }
        let Some(seal_ns) = seal_rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
            .map(|inst| inst.to_epoch_ns())
        else {
            continue;
        };
        for cov_ref in covered_refs {
            qualifying_seals_by_target
                .entry(cov_ref.clone())
                .or_default()
                .push((seal_ref.clone(), seal_ns));
        }
    }

    // 3. Collect counting retention records (`A7` §4.2), `T_end(S)` per retention stream,
    //    and per-retention-stream `(seq -> Vec<rec_idx>)` for Row 6 continuity checks.
    let mut counting_by_idx = vec![false; opened_records.len()];
    let mut holds_by_stream: BTreeMap<String, Vec<CountingHold>> = BTreeMap::new();
    let mut releases_by_stream: BTreeMap<String, Vec<CountingRelease>> = BTreeMap::new();
    let mut disposals_by_stream: BTreeMap<String, Vec<CountingDisposal>> = BTreeMap::new();
    let mut t_end_by_stream: BTreeMap<String, i128> = BTreeMap::new();
    let mut retention_stream_positions: BTreeMap<String, BTreeMap<i64, Vec<usize>>> =
        BTreeMap::new();
    let mut retention_stream_total_records: BTreeMap<String, usize> = BTreeMap::new();

    for (idx, rec) in opened_records.iter().enumerate() {
        let Some(stream) = rec.payload.get("stream").and_then(Value::as_str) else {
            continue;
        };
        if !is_retention_stream_uri(stream) {
            continue;
        }
        *retention_stream_total_records
            .entry(stream.to_string())
            .or_insert(0) += 1;
        if let Some(seq) = rec.payload.get("seq").and_then(parse_v2_integer)
            && seq >= 1
        {
            retention_stream_positions
                .entry(stream.to_string())
                .or_default()
                .entry(seq)
                .or_default()
                .push(idx);
        }

        let kp = rec.kind_path();
        if !matches!(
            kp.as_deref(),
            Some(KIND_RETENTION_HOLD | KIND_RETENTION_HOLD_RELEASE | KIND_PAYLOAD_DISPOSITION)
        ) {
            continue;
        }
        if !rec.all_sigs_ok || body_result_by_idx[idx] != "ok" || !authority_ok_by_idx[idx] {
            continue;
        }
        let (Some(seq), Some(cap_ns), Some(body)) = (
            rec.payload.get("seq").and_then(parse_v2_integer),
            rec.payload
                .get("capturedAt")
                .and_then(Value::as_str)
                .and_then(|s| parse_rfc3339_instant(s, None, false))
                .map(|inst| inst.to_epoch_ns()),
            rec.payload.get("body"),
        ) else {
            continue;
        };

        counting_by_idx[idx] = true;
        t_end_by_stream
            .entry(stream.to_string())
            .and_modify(|cur| {
                if cap_ns > *cur {
                    *cur = cap_ns;
                }
            })
            .or_insert(cap_ns);

        match kp.as_deref() {
            Some(KIND_RETENTION_HOLD) => {
                let Some(tos) = TargetOrScope::from_body(body) else {
                    continue;
                };
                let until_ns = body
                    .get("until")
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, Some(9), false))
                    .map(|inst| inst.to_epoch_ns());
                holds_by_stream
                    .entry(stream.to_string())
                    .or_default()
                    .push(CountingHold {
                        rec_ref: rec.rec_ref.clone(),
                        stream: stream.to_string(),
                        seq,
                        until_ns,
                        target_or_scope: tos,
                    });
            }
            Some(KIND_RETENTION_HOLD_RELEASE) => {
                if let Some(hold_ref) = body.get("hold").and_then(Value::as_str) {
                    releases_by_stream
                        .entry(stream.to_string())
                        .or_default()
                        .push(CountingRelease {
                            stream: stream.to_string(),
                            seq,
                            hold_ref: hold_ref.to_string(),
                        });
                }
            }
            Some(KIND_PAYLOAD_DISPOSITION) => {
                let Some(tos) = TargetOrScope::from_body(body) else {
                    continue;
                };
                let action_disposes = matches!(
                    body.get("action").and_then(Value::as_str),
                    Some("expired" | "deleted")
                );
                disposals_by_stream
                    .entry(stream.to_string())
                    .or_default()
                    .push(CountingDisposal {
                        rec_ref: rec.rec_ref.clone(),
                        stream: stream.to_string(),
                        seq,
                        captured_at_ns: cap_ns,
                        action_disposes,
                        target_or_scope: tos,
                    });
            }
            _ => {}
        }
    }

    for holds in holds_by_stream.values_mut() {
        holds.sort_by(|a, b| {
            a.seq
                .cmp(&b.seq)
                .then_with(|| a.rec_ref.as_bytes().cmp(b.rec_ref.as_bytes()))
        });
    }
    for disposals in disposals_by_stream.values_mut() {
        disposals.sort_by(|a, b| {
            a.seq
                .cmp(&b.seq)
                .then_with(|| a.rec_ref.as_bytes().cmp(b.rec_ref.as_bytes()))
        });
    }

    // 4. Evaluate `content` findings per opened record `R` (`A7` §5).
    for rec in opened_records {
        let body_refs = collect_record_content_refs(rec);
        if body_refs.is_empty() {
            continue;
        }

        let r_ret_stream = rec
            .payload
            .get("stream")
            .and_then(Value::as_str)
            .and_then(retention_stream_of);
        let r_scope = content_scope_of(rec);
        let r_cap_ns = rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
            .map(|inst| inst.to_epoch_ns());
        let r_profile_ref = rec.payload.get("profileRef").and_then(Value::as_str);
        let r_profile_ret = r_profile_ref.and_then(|pr| valid_profile_retentions.get(pr).copied());

        for bref in body_refs {
            if valid_blobs.contains_key(&bref) || base_defs.contains_index_ref(&bref) {
                findings.push(Finding::new(
                    2,
                    &rec.rec_ref,
                    "content",
                    "ok",
                    "ok",
                    Some(bref),
                ));
                continue;
            }

            // §5.1: Select earliest `(D.seq, D.ref)` counting disposal covering `(R, B)`.
            let selected_disposal = match (&r_ret_stream, r_cap_ns) {
                (Some(ret_st), Some(rc_ns)) => disposals_by_stream.get(ret_st).and_then(|ds| {
                    ds.iter().find(|d| {
                        debug_assert_eq!(d.stream, *ret_st);
                        d.action_disposes
                            && rc_ns <= d.captured_at_ns
                            && d.target_or_scope
                                .matches(&rec.rec_ref, r_scope.as_deref(), &bref)
                    })
                }),
                _ => None,
            };

            if let Some(d) = selected_disposal {
                let rc_ns = r_cap_ns.expect("disposal selection requires valid R.capturedAt");
                let empty_holds = Vec::new();
                let empty_rels = Vec::new();
                let holds_on_st = holds_by_stream.get(&d.stream).unwrap_or(&empty_holds);
                let rels_on_st = releases_by_stream.get(&d.stream).unwrap_or(&empty_rels);

                // Row 1 (`disposed_under_hold`): `holds_on_st` is already sorted by `(H.seq, H.ref)`.
                if let Some(active_h) = holds_on_st.iter().find(|h| {
                    debug_assert_eq!(h.stream, d.stream);
                    if h.seq >= d.seq {
                        return false;
                    }
                    if !h
                        .target_or_scope
                        .matches(&rec.rec_ref, r_scope.as_deref(), &bref)
                    {
                        return false;
                    }
                    let released_before_d = rels_on_st.iter().any(|rel| {
                        debug_assert_eq!(rel.stream, d.stream);
                        h.seq < rel.seq && rel.seq < d.seq && rel.hold_ref == h.rec_ref
                    });
                    if released_before_d {
                        return false;
                    }
                    h.until_ns.is_none_or(|u_ns| d.captured_at_ns < u_ns)
                }) {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "failed",
                        "disposed_under_hold",
                        Some(active_h.rec_ref.clone()),
                    ));
                    continue;
                }

                // Row 2 (`disposed_before_keep_until`)
                if let Some(prof_ret) = r_profile_ret {
                    let violates_keep = match prof_ret {
                        ParsedProfileRetention::Never => true,
                        ParsedProfileRetention::ByRecord {
                            keep_content_for_seconds,
                        } => {
                            let keep_until_ns =
                                rc_ns + (keep_content_for_seconds as i128) * 1_000_000_000;
                            keep_until_ns > d.captured_at_ns
                        }
                    };
                    if violates_keep {
                        findings.push(Finding::new(
                            2,
                            &rec.rec_ref,
                            "content",
                            "failed",
                            "disposed_before_keep_until",
                            Some(d.rec_ref.clone()),
                        ));
                        continue;
                    }
                }

                // Row 3 (`disposal_dated_after_its_seal`)
                let seals_for_d = qualifying_seals_by_target.get(&d.rec_ref);
                if let Some(seals) = seals_for_d
                    && let Some(min_seal_ref) = seals
                        .iter()
                        .filter(|(_, s_ns)| d.captured_at_ns > *s_ns)
                        .map(|(s_ref, _)| s_ref.as_str())
                        .min_by(|a, b| a.as_bytes().cmp(b.as_bytes()))
                {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "failed",
                        "disposal_dated_after_its_seal",
                        Some(min_seal_ref.to_string()),
                    ));
                    continue;
                }

                // Row 4 (`disposed_profile_not_shown`)
                if r_profile_ret.is_none() {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "incomplete",
                        "disposed_profile_not_shown",
                        r_profile_ref.map(str::to_string),
                    ));
                    continue;
                }

                // Row 5 (`disposal_not_sealed`)
                if seals_for_d.is_none_or(Vec::is_empty) {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "incomplete",
                        "disposal_not_sealed",
                        Some(d.rec_ref.clone()),
                    ));
                    continue;
                }

                // Row 6 (`disposed_holds_not_shown`)
                let holds_shown = check_retention_prefix_shown(
                    &d.stream,
                    d.seq,
                    &d.rec_ref,
                    &retention_stream_positions,
                    &retention_stream_total_records,
                    opened_records,
                    &counting_by_idx,
                );
                if !holds_shown {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "incomplete",
                        "disposed_holds_not_shown",
                        Some(d.rec_ref.clone()),
                    ));
                    continue;
                }

                // Row 7 (`disposed_by_record`)
                findings.push(Finding::new(
                    2,
                    &rec.rec_ref,
                    "content",
                    "incomplete",
                    "disposed_by_record",
                    Some(d.rec_ref.clone()),
                ));
                continue;
            }

            // §5.3: No counting disposal covers `(R, B)` (Rows 8–10).
            let first_omission = omissions_by_ref.get(&bref).map(String::as_str);

            // Row 8 (`missing_under_hold`)
            let check_hold = !matches!(first_omission, Some("not-selected" | "withheld"));
            if check_hold && let Some(ret_st) = &r_ret_stream {
                let empty_holds = Vec::new();
                let empty_rels = Vec::new();
                let holds_on_st = holds_by_stream.get(ret_st).unwrap_or(&empty_holds);
                let rels_on_st = releases_by_stream.get(ret_st).unwrap_or(&empty_rels);
                let t_end_opt = t_end_by_stream.get(ret_st).copied();

                if let Some(active_h) = holds_on_st.iter().find(|h| {
                    if !h
                        .target_or_scope
                        .matches(&rec.rec_ref, r_scope.as_deref(), &bref)
                    {
                        return false;
                    }
                    let released = rels_on_st
                        .iter()
                        .any(|rel| rel.seq > h.seq && rel.hold_ref == h.rec_ref);
                    if released {
                        return false;
                    }
                    match h.until_ns {
                        None => true,
                        Some(u_ns) => {
                            let t_end =
                                t_end_opt.expect("counting hold implies T_end exists on stream");
                            t_end < u_ns
                        }
                    }
                }) {
                    findings.push(Finding::new(
                        2,
                        &rec.rec_ref,
                        "content",
                        "incomplete",
                        "missing_under_hold",
                        Some(active_h.rec_ref.clone()),
                    ));
                    continue;
                }
            }

            // Row 9 (`omitted_<reason>`)
            if let Some(reason) = first_omission {
                let code = format!("omitted_{}", reason.replace('-', "_"));
                findings.push(Finding::new(
                    2,
                    &rec.rec_ref,
                    "content",
                    "incomplete",
                    code,
                    Some(bref),
                ));
            } else {
                // Row 10 (`not_carried`)
                findings.push(Finding::new(
                    2,
                    &rec.rec_ref,
                    "content",
                    "incomplete",
                    "not_carried",
                    Some(bref),
                ));
            }
        }
    }
}

fn check_retention_prefix_shown(
    stream: &str,
    d_seq: i64,
    d_ref: &str,
    retention_stream_positions: &BTreeMap<String, BTreeMap<i64, Vec<usize>>>,
    retention_stream_total_records: &BTreeMap<String, usize>,
    opened_records: &[OpenedRecord],
    counting_by_idx: &[bool],
) -> bool {
    if d_seq < 1 {
        return false;
    }
    let total_on_stream = retention_stream_total_records
        .get(stream)
        .copied()
        .unwrap_or(0);
    let Ok(d_seq_usize) = usize::try_from(d_seq) else {
        return false;
    };
    if d_seq_usize > total_on_stream {
        return false;
    }
    let Some(by_seq) = retention_stream_positions.get(stream) else {
        return false;
    };

    let mut prev_ref: Option<&str> = None;
    for k in 1..=d_seq {
        let Some(indices) = by_seq.get(&k) else {
            return false;
        };
        if indices.len() != 1 {
            return false;
        }
        let rec_idx = indices[0];
        let rk = &opened_records[rec_idx];
        if k == d_seq && rk.rec_ref != d_ref {
            return false;
        }
        if k == 1 {
            if !rk.payload.get("previous").is_some_and(Value::is_null) {
                return false;
            }
        } else if rk.payload.get("previous").and_then(Value::as_str) != prev_ref {
            return false;
        }
        if k < d_seq
            && rk.kind_path().as_deref() == Some(KIND_RETENTION_HOLD)
            && !counting_by_idx[rec_idx]
        {
            return false;
        }
        prev_ref = Some(rk.rec_ref.as_str());
    }
    true
}
