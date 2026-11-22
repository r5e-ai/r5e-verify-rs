#![allow(clippy::too_many_arguments)]

use super::canonical::{UtcInstant, parse_rfc3339_instant};
use super::{Finding, OpenedRecord};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const KIND_PRINCIPAL: &str = "provenance.r5e.io/v2/Principal";
pub const KIND_SUCCESSION: &str = "provenance.r5e.io/v2/Succession";
pub const KIND_DEFINITION_PUBLISHED: &str = "provenance.r5e.io/v2/DefinitionPublished";
pub const KIND_CHAIN_STARTED: &str = "provenance.r5e.io/v2/ChainStarted";
pub const KIND_DEPLOYMENT: &str = "provenance.r5e.io/v2/Deployment";
pub const KIND_ROOTS_CHANGED: &str = "provenance.r5e.io/v2/RootsChanged";
pub const KIND_ROOT_CHANGE_APPROVAL: &str = "provenance.r5e.io/v2/RootChangeApproval";
pub const KIND_ENDORSEMENT: &str = "provenance.r5e.io/v2/Endorsement";
pub const KIND_BADGE: &str = "provenance.r5e.io/v2/Badge";
pub const KIND_REVOCATION: &str = "provenance.r5e.io/v2/Revocation";
pub const KIND_EPOCH_SEAL: &str = "provenance.r5e.io/v2/EpochSeal";

pub fn is_exempt_from_a5_authority(kind_path: Option<&str>) -> bool {
    matches!(
        kind_path,
        Some(
            KIND_PRINCIPAL
                | KIND_SUCCESSION
                | KIND_DEFINITION_PUBLISHED
                | KIND_CHAIN_STARTED
                | KIND_DEPLOYMENT
                | KIND_ROOTS_CHANGED
                | KIND_ROOT_CHANGE_APPROVAL
        )
    )
}

const MAX_CHAIN_LINKS: usize = 16;
const MAX_SUCCESSION_STEPS: usize = 16;

/// One period of office `(key, admitted_at, ended_by)` for a deployment root (`A6` Slice 2 §4.2).
/// `admitted_at: None` represents `-∞` (direct `--trusted-root` pin without a carried start stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootTenure {
    pub(crate) key: String,
    pub(crate) admitted_at: Option<UtcInstant>,
    pub(crate) ended_by: Option<(String, UtcInstant)>,
}

#[derive(Debug, Clone)]
enum RootTenureMatch {
    /// Key holds zero root tenures.
    NoTenure,
    /// Key holds `>= 1` root tenure, all with `admitted_at > at`.
    PredatesAdmission,
    /// Key holds `>= 1` root tenure with `admitted_at <= at` and `ended_by == None`.
    Open,
    /// Every tenure of `key` with `admitted_at <= at` is closed; `T_latest` (max `admitted_at`)
    /// ended at `(end_ref, end_time)`.
    Closed {
        end_ref: String,
        end_time: UtcInstant,
    },
}

fn has_any_root_tenure(tenures: &[RootTenure], key: &str) -> bool {
    tenures.iter().any(|t| t.key == key)
}

fn evaluate_root_tenure(tenures: &[RootTenure], key: &str, at: &UtcInstant) -> RootTenureMatch {
    let mut any_for_key = false;
    let mut latest_closed: Option<(&Option<UtcInstant>, &(String, UtcInstant))> = None;
    for t in tenures {
        if t.key != key {
            continue;
        }
        any_for_key = true;
        if t.admitted_at.as_ref().is_some_and(|adm| at < adm) {
            continue;
        }
        match &t.ended_by {
            None => return RootTenureMatch::Open,
            Some(end_pair) => {
                if latest_closed
                    .as_ref()
                    .is_none_or(|(best_adm, _)| &t.admitted_at > *best_adm)
                {
                    latest_closed = Some((&t.admitted_at, end_pair));
                }
            }
        }
    }
    if let Some((_, (end_ref, end_time))) = latest_closed {
        RootTenureMatch::Closed {
            end_ref: end_ref.clone(),
            end_time: end_time.clone(),
        }
    } else if any_for_key {
        RootTenureMatch::PredatesAdmission
    } else {
        RootTenureMatch::NoTenure
    }
}

#[derive(Debug, Clone)]
struct LinkNode {
    rec_ref: String,
    is_badge: bool,
    issuer: String,
    captured_at: UtcInstant,
    subject: String,
    kinds: BTreeSet<String>,
    may_endorse: bool,
    not_before: UtcInstant,
    not_after: UtcInstant,
    parent: Option<String>,
    stream_prefixes: Option<Vec<String>>,
    actor_prefixes: Option<Vec<String>>,
    acts_for: Option<String>,
}

#[derive(Debug, Clone)]
struct SuccessionEdge {
    rec_ref: String,
    predecessor: String,
    successor: String,
    captured_at: UtcInstant,
}

#[derive(Debug, Clone)]
struct RevocationRecord {
    rec_ref: String,
    issuer: String,
    captured_at: UtcInstant,
    target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndingSignerKind {
    FromAbove,
    SelfKey,
}

#[derive(Debug, Clone)]
struct ApplicableEnding {
    rec_ref: String,
    captured_at: UtcInstant,
    signer_kind: EndingSignerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndingComparison {
    ShownToPrecede,
    SignersClock,
    Applies,
}

#[derive(Debug, Clone)]
struct StepInfo<'a> {
    rec_ref: &'a str,
    issuer: &'a str,
    captured_at: &'a UtcInstant,
    is_root_step: bool,
    root_ending: Option<ApplicableEnding>,
}

/// §7 Succession graph (for non-root `Endorsement` subjects, `A6` Slice 2 §4.1):
/// handles linear chains (`<= 16` steps), competing forks from one predecessor
/// (`>= 2` distinct successors), and cycles (`<= 16` steps).
struct SuccessionIndex {
    /// Outgoing succession edges per predecessor, sorted by `(captured_at, rec_ref)`.
    by_pred: BTreeMap<String, Vec<SuccessionEdge>>,
    /// Unique valid stand-in outgoing edge per predecessor (absent for forks and cycle members).
    unique_next: BTreeMap<String, SuccessionEdge>,
    /// Earliest succession edge in any cycle containing a key.
    cycle_endings: BTreeMap<String, Vec<SuccessionEdge>>,
}

impl SuccessionIndex {
    fn build(edges: Vec<SuccessionEdge>) -> Self {
        let mut by_pred: BTreeMap<String, Vec<SuccessionEdge>> = BTreeMap::new();
        for e in edges {
            by_pred.entry(e.predecessor.clone()).or_default().push(e);
        }
        for list in by_pred.values_mut() {
            list.sort_by(|a, b| {
                a.captured_at
                    .cmp(&b.captured_at)
                    .then_with(|| a.rec_ref.as_bytes().cmp(b.rec_ref.as_bytes()))
            });
        }

        // A predecessor with >= 2 distinct successors is forked: neither successor stands in for it.
        let mut raw_unique_next: BTreeMap<String, SuccessionEdge> = BTreeMap::new();
        let mut self_loop_endings: BTreeMap<String, Vec<SuccessionEdge>> = BTreeMap::new();
        for (pred, list) in &by_pred {
            let distinct_succs: BTreeSet<&str> =
                list.iter().map(|e| e.successor.as_str()).collect();
            if distinct_succs.len() == 1 {
                let first = &list[0];
                if first.successor == *pred {
                    self_loop_endings
                        .entry(pred.clone())
                        .or_default()
                        .push(first.clone());
                } else {
                    raw_unique_next.insert(pred.clone(), first.clone());
                }
            }
        }

        // Detect loops in `raw_unique_next`.
        let mut cycle_keys: BTreeSet<String> = self_loop_endings.keys().cloned().collect();
        let mut cycle_endings: BTreeMap<String, Vec<SuccessionEdge>> = self_loop_endings;
        let max_graph_steps = raw_unique_next.len();

        for start_key in raw_unique_next.keys() {
            let mut path_keys: Vec<String> = vec![start_key.clone()];
            let mut path_edges: Vec<SuccessionEdge> = Vec::new();
            let mut curr = start_key.as_str();

            for _ in 0..=max_graph_steps {
                let Some(edge) = raw_unique_next.get(curr) else {
                    break;
                };
                path_edges.push(edge.clone());
                if edge.successor == *start_key {
                    let min_time = &path_edges
                        .iter()
                        .min_by(|a, b| a.captured_at.cmp(&b.captured_at))
                        .unwrap()
                        .captured_at;
                    let earliest_edges: Vec<SuccessionEdge> = path_edges
                        .iter()
                        .filter(|e| &e.captured_at == min_time)
                        .cloned()
                        .collect();
                    for k in &path_keys {
                        cycle_keys.insert(k.clone());
                        let entry = cycle_endings.entry(k.clone()).or_default();
                        for me in &earliest_edges {
                            if !entry.iter().any(|e| e.rec_ref == me.rec_ref) {
                                entry.push(me.clone());
                            }
                        }
                    }
                    break;
                }
                if path_keys.iter().any(|k| k == &edge.successor) {
                    break;
                }
                path_keys.push(edge.successor.clone());
                curr = path_keys.last().unwrap().as_str();
            }
        }

        let mut unique_next = BTreeMap::new();
        for (pred, edge) in raw_unique_next {
            if !cycle_keys.contains(&pred) {
                unique_next.insert(pred, edge);
            }
        }

        Self {
            by_pred,
            unique_next,
            cycle_endings,
        }
    }

    /// Returns true when `signer == target_key`, or when `signer` succeeds `target_key`
    /// through `1..=16` valid non-forked, non-cyclic hand-overs whose `capturedAt` are
    /// all `<= at` (§7). Used only for non-root `Endorsement` subjects (`A6` Slice 2 §4.1).
    fn stands_in_for(&self, signer: &str, target_key: &str, at: &UtcInstant) -> bool {
        if signer == target_key {
            return true;
        }
        let mut curr = target_key;
        let mut visited = BTreeSet::new();
        visited.insert(curr);
        for _ in 0..MAX_SUCCESSION_STEPS {
            let Some(edge) = self.unique_next.get(curr) else {
                return false;
            };
            if at < &edge.captured_at {
                return false;
            }
            if edge.successor == signer {
                return true;
            }
            if !visited.insert(edge.successor.as_str()) {
                return false;
            }
            curr = edge.successor.as_str();
        }
        false
    }

    /// Collects all `Succession` endings touching non-root steps signed by `key` (both direct
    /// outgoing successions from `key` and earliest cycle successions if `key` is in a cycle).
    fn succession_endings_for_key(&self, key: &str) -> Vec<ApplicableEnding> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        if let Some(list) = self.by_pred.get(key) {
            for e in list {
                if seen.insert(e.rec_ref.clone()) {
                    out.push(ApplicableEnding {
                        rec_ref: e.rec_ref.clone(),
                        captured_at: e.captured_at.clone(),
                        signer_kind: EndingSignerKind::SelfKey,
                    });
                }
            }
        }
        if let Some(list) = self.cycle_endings.get(key) {
            for e in list {
                if seen.insert(e.rec_ref.clone()) {
                    out.push(ApplicableEnding {
                        rec_ref: e.rec_ref.clone(),
                        captured_at: e.captured_at.clone(),
                        signer_kind: EndingSignerKind::SelfKey,
                    });
                }
            }
        }
        out
    }

    /// Earliest hand-over timestamp (`capturedAt`) ending `key` via `Succession`, if `key` has handed over.
    fn earliest_handover_time(&self, key: &str) -> Option<&UtcInstant> {
        let a = self
            .by_pred
            .get(key)
            .and_then(|l| l.iter().map(|e| &e.captured_at).min());
        let b = self
            .cycle_endings
            .get(key)
            .and_then(|l| l.iter().map(|e| &e.captured_at).min());
        match (a, b) {
            (Some(x), Some(y)) => Some(if x <= y { x } else { y }),
            (Some(x), None) => Some(x),
            (None, Some(y)) => Some(y),
            (None, None) => None,
        }
    }
}

fn parse_optional_string_array(body: &Value, field: &str) -> Option<Option<Vec<String>>> {
    let Some(val) = body.get(field) else {
        return Some(None);
    };
    let arr = val.as_array()?;
    if arr.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str()?;
        if s.is_empty() {
            return None;
        }
        out.push(s.to_string());
    }
    Some(Some(out))
}

fn parse_link_node(rec: &OpenedRecord) -> Option<LinkNode> {
    let kind_path = rec.kind_path()?;
    let is_badge = match kind_path.as_str() {
        KIND_ENDORSEMENT => false,
        KIND_BADGE => true,
        _ => return None,
    };
    let captured_str = rec.payload.get("capturedAt")?.as_str()?;
    let captured_at = parse_rfc3339_instant(captured_str, None, false)?;
    let body = rec.payload.get("body")?.as_object()?;

    let subject = body.get("subject")?.as_str()?.to_string();
    let kinds_arr = body.get("kinds")?.as_array()?;
    if kinds_arr.is_empty() {
        return None;
    }
    let mut kinds = BTreeSet::new();
    for kv in kinds_arr {
        kinds.insert(kv.as_str()?.to_string());
    }

    let may_endorse = if is_badge {
        false
    } else {
        body.get("mayEndorse")?.as_bool()?
    };

    let nb_str = body.get("notBefore")?.as_str()?;
    let na_str = body.get("notAfter")?.as_str()?;
    let not_before = parse_rfc3339_instant(nb_str, None, false)?;
    let not_after = parse_rfc3339_instant(na_str, None, false)?;
    if not_before > not_after {
        return None;
    }

    let parent = match body.get("parent") {
        None => {
            if is_badge {
                return None;
            }
            None
        }
        Some(v) => Some(v.as_str()?.to_string()),
    };

    let stream_prefixes = parse_optional_string_array(&rec.payload["body"], "streamPrefixes")?;
    let actor_prefixes = parse_optional_string_array(&rec.payload["body"], "actorPrefixes")?;
    let acts_for = match body.get("actsFor") {
        None => None,
        Some(v) => Some(v.as_str()?.to_string()),
    };

    Some(LinkNode {
        rec_ref: rec.rec_ref.clone(),
        is_badge,
        issuer: rec.signers[0].clone(),
        captured_at,
        subject,
        kinds,
        may_endorse,
        not_before,
        not_after,
        parent,
        stream_prefixes,
        actor_prefixes,
        acts_for,
    })
}

/// §3. A link covers an ordinary record when kind, streamPrefixes (`body.stream` for `EpochSeal`),
/// actorPrefixes, actsFor/`onBehalfOf`, and `[notBefore, notAfter]` all hold.
fn link_covers_record(link: &LinkNode, rec: &OpenedRecord, rec_captured_at: &UtcInstant) -> bool {
    let Some(kind_path) = rec.kind_path() else {
        return false;
    };
    if !link.kinds.contains(&kind_path) {
        return false;
    }

    if let Some(prefs) = &link.stream_prefixes {
        let stream_opt = if kind_path == KIND_EPOCH_SEAL {
            rec.payload
                .get("body")
                .and_then(|b| b.get("stream"))
                .and_then(Value::as_str)
        } else {
            rec.payload.get("stream").and_then(Value::as_str)
        };
        let Some(stream) = stream_opt else {
            return false;
        };
        if !prefs.iter().any(|p| stream.starts_with(p.as_str())) {
            return false;
        }
    }

    if let Some(prefs) = &link.actor_prefixes {
        let Some(actor) = rec.payload.get("actor").and_then(Value::as_str) else {
            return false;
        };
        if !prefs.iter().any(|p| actor.starts_with(p.as_str())) {
            return false;
        }
    }

    if let Some(acts_for) = &link.acts_for
        && rec.payload.get("onBehalfOf").and_then(Value::as_str) != Some(acts_for.as_str())
    {
        return false;
    }

    link.not_before <= *rec_captured_at && *rec_captured_at <= link.not_after
}

/// §4.4 (`A6` Slice 2): checks whether `link` covers `seal_rec` as an `EpochSeal` on
/// `seal_rec.body.stream` for *some* window `[link.not_before, link.not_after]`.
fn link_covers_seal_for_some_window(link: &LinkNode, seal_rec: &OpenedRecord) -> bool {
    if !link.kinds.contains(KIND_EPOCH_SEAL) {
        return false;
    }
    if let Some(prefs) = &link.stream_prefixes {
        let Some(stream) = seal_rec
            .payload
            .get("body")
            .and_then(|b| b.get("stream"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        if !prefs.iter().any(|p| stream.starts_with(p.as_str())) {
            return false;
        }
    }
    if let Some(prefs) = &link.actor_prefixes {
        let Some(actor) = seal_rec.payload.get("actor").and_then(Value::as_str) else {
            return false;
        };
        if !prefs.iter().any(|p| actor.starts_with(p.as_str())) {
            return false;
        }
    }
    if let Some(acts_for) = &link.acts_for
        && seal_rec.payload.get("onBehalfOf").and_then(Value::as_str) != Some(acts_for.as_str())
    {
        return false;
    }
    link.not_before <= link.not_after
}

/// §4.5 & §4.6. Child link `child` never grants more than `parent`, and was issued
/// while `parent` was in force.
fn child_narrows_and_fits_parent(child: &LinkNode, parent: &LinkNode) -> bool {
    if !child.kinds.is_subset(&parent.kinds) {
        return false;
    }
    if child.not_before < parent.not_before || child.not_after > parent.not_after {
        return false;
    }
    if let Some(p_prefs) = &parent.stream_prefixes {
        let Some(c_prefs) = &child.stream_prefixes else {
            return false;
        };
        if !c_prefs
            .iter()
            .all(|cp| p_prefs.iter().any(|pp| cp.starts_with(pp.as_str())))
        {
            return false;
        }
    }
    if let Some(p_prefs) = &parent.actor_prefixes {
        let Some(c_prefs) = &child.actor_prefixes else {
            return false;
        };
        if !c_prefs
            .iter()
            .all(|cp| p_prefs.iter().any(|pp| cp.starts_with(pp.as_str())))
        {
            return false;
        }
    }
    if let Some(p_af) = &parent.acts_for
        && child.acts_for.as_deref() != Some(p_af.as_str())
    {
        return false;
    }
    parent.not_before <= child.captured_at && child.captured_at <= parent.not_after
}

enum LineageWalk<'a> {
    /// Complete §4 chain `links[0] = L0 .. links[n] = bottom_link` rooted in `tenures`
    /// (`admitted_at <= L0.capturedAt`, open or closed).
    FullCandidate(Vec<&'a LinkNode>),
    /// Carried suffix `links[0] = L_top .. links[k] = bottom_link` (`len <= 15`) whose
    /// `L_top.parent` is missing / incomplete.
    MissingParent {
        carried_links: Vec<&'a LinkNode>,
        missing_ref: String,
    },
    /// Invalid (fails §4 or top link does not match a root tenure at `L0.capturedAt`).
    Invalid,
}

/// §5: A reference *might yet be a valid grant* when it is not among the opened records at all,
/// or when it is an opened `Endorsement` or `Badge` that is not authority-stating only because
/// a check could not be performed (a `signature` or `body` finding is `incomplete` and none is `failed`).
fn might_yet_be_valid_grant(
    ref_str: &str,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
) -> bool {
    let Some(&idx) = opened_by_ref.get(ref_str) else {
        return true;
    };
    let rec = &opened_records[idx];
    if !matches!(
        rec.kind_path().as_deref(),
        Some(KIND_ENDORSEMENT | KIND_BADGE)
    ) {
        return false;
    }
    if any_sig_failed_by_idx[idx] || body_result_by_idx[idx] == "failed" {
        return false;
    }
    !(rec.all_sigs_ok && body_result_by_idx[idx] == "ok")
}

/// Walks upward from `bottom_link` through `valid_links` enforcing §4.1–§4.7 and `A6` Slice 2 §4.1–§4.3.
fn walk_lineage<'a>(
    bottom_link: &'a LinkNode,
    valid_links: &'a BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    covered_ordinary: Option<(&OpenedRecord, &UtcInstant)>,
) -> LineageWalk<'a> {
    if bottom_link.issuer == bottom_link.subject {
        return LineageWalk::Invalid;
    }
    if let Some((ord_rec, ord_time)) = covered_ordinary
        && !link_covers_record(bottom_link, ord_rec, ord_time)
    {
        return LineageWalk::Invalid;
    }

    let mut rev_links: Vec<&'a LinkNode> = vec![bottom_link];
    let mut seen_refs: BTreeSet<&str> = BTreeSet::new();
    seen_refs.insert(bottom_link.rec_ref.as_str());

    loop {
        let curr = *rev_links.last().unwrap();
        match &curr.parent {
            None => {
                if curr.is_badge {
                    return LineageWalk::Invalid;
                }
                match evaluate_root_tenure(tenures, &curr.issuer, &curr.captured_at) {
                    RootTenureMatch::Open | RootTenureMatch::Closed { .. } => {
                        rev_links.reverse();
                        return LineageWalk::FullCandidate(rev_links);
                    }
                    RootTenureMatch::NoTenure | RootTenureMatch::PredatesAdmission => {
                        return LineageWalk::Invalid;
                    }
                }
            }
            Some(p_ref) => {
                if rev_links.len() >= MAX_CHAIN_LINKS {
                    return LineageWalk::Invalid;
                }
                if !seen_refs.insert(p_ref.as_str()) {
                    return LineageWalk::Invalid;
                }
                match valid_links.get(p_ref) {
                    Some(parent_link) => {
                        if parent_link.is_badge || !parent_link.may_endorse {
                            return LineageWalk::Invalid;
                        }
                        if !succ.stands_in_for(
                            &curr.issuer,
                            &parent_link.subject,
                            &curr.captured_at,
                        ) {
                            return LineageWalk::Invalid;
                        }
                        if !child_narrows_and_fits_parent(curr, parent_link) {
                            return LineageWalk::Invalid;
                        }
                        if let Some((ord_rec, ord_time)) = covered_ordinary
                            && !link_covers_record(parent_link, ord_rec, ord_time)
                        {
                            return LineageWalk::Invalid;
                        }
                        rev_links.push(parent_link);
                    }
                    None => {
                        if might_yet_be_valid_grant(
                            p_ref,
                            opened_records,
                            opened_by_ref,
                            any_sig_failed_by_idx,
                            body_result_by_idx,
                        ) {
                            rev_links.reverse();
                            return LineageWalk::MissingParent {
                                carried_links: rev_links,
                                missing_ref: p_ref.clone(),
                            };
                        }
                        return LineageWalk::Invalid;
                    }
                }
            }
        }
    }
}

struct TargetLineage<'a> {
    ancestors: Vec<&'a LinkNode>,
    missing_top_parent: Option<String>,
}

/// Walks carried valid ancestor links above `target` (`parent`, `parent.parent`, ..., up to 16 links total)
/// for §5/`§6` revocation entitlement, also recording whether the top carried link (`target` or its highest
/// carried valid ancestor) names a `parent` that might yet be a valid grant.
fn inspect_target_lineage<'a>(
    target: &'a LinkNode,
    valid_links: &'a BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    succ: &SuccessionIndex,
) -> TargetLineage<'a> {
    let mut ancestors = Vec::new();
    let mut seen = BTreeSet::new();
    seen.insert(target.rec_ref.as_str());
    let mut curr = target;
    let mut missing_top_parent = None;

    while ancestors.len() + 1 < MAX_CHAIN_LINKS {
        let Some(p_ref) = &curr.parent else {
            break;
        };
        if !seen.insert(p_ref.as_str()) {
            break;
        }
        match valid_links.get(p_ref) {
            Some(parent_link) => {
                if parent_link.is_badge || !parent_link.may_endorse {
                    break;
                }
                if !succ.stands_in_for(&curr.issuer, &parent_link.subject, &curr.captured_at) {
                    break;
                }
                if !child_narrows_and_fits_parent(curr, parent_link) {
                    break;
                }
                ancestors.push(parent_link);
                curr = parent_link;
            }
            None => {
                if might_yet_be_valid_grant(
                    p_ref,
                    opened_records,
                    opened_by_ref,
                    any_sig_failed_by_idx,
                    body_result_by_idx,
                ) {
                    missing_top_parent = Some(p_ref.clone());
                }
                break;
            }
        }
    }
    TargetLineage {
        ancestors,
        missing_top_parent,
    }
}

fn target_reaches_deployment_root(
    target: &LinkNode,
    ancestors: &[&LinkNode],
    tenures: &[RootTenure],
) -> bool {
    let top = ancestors.last().copied().unwrap_or(target);
    top.parent.is_none() && !top.is_badge && has_any_root_tenure(tenures, &top.issuer)
}

fn non_root_revocation_role(
    rev_issuer: &str,
    rev_time: &UtcInstant,
    target: &LinkNode,
    ancestors: &[&LinkNode],
    succ: &SuccessionIndex,
) -> Option<EndingSignerKind> {
    if std::iter::once(target)
        .chain(ancestors.iter().copied())
        .any(|lnk| lnk.parent.is_some() && succ.stands_in_for(rev_issuer, &lnk.issuer, rev_time))
    {
        return Some(EndingSignerKind::FromAbove);
    }
    if succ.stands_in_for(rev_issuer, &target.subject, rev_time) {
        return Some(EndingSignerKind::SelfKey);
    }
    None
}

fn non_root_satisfies_handover_rule(
    rev_issuer: &str,
    rev_ref: &str,
    succ: &SuccessionIndex,
    shown_times_by_ref: Option<&BTreeMap<String, Vec<UtcInstant>>>,
) -> bool {
    let Some(e_handover) = succ.earliest_handover_time(rev_issuer) else {
        return true;
    };
    shown_times_by_ref
        .and_then(|m| m.get(rev_ref))
        .is_some_and(|seals| seals.iter().any(|s| s < e_handover))
}

/// Checks whether a `Revocation` (`rev_issuer`, `rev_time`, `rev_ref`) is an entitled active
/// revocation on `target` (`A5` §6 + `A6` Slice 2 §4.3.2). When `shown_times_by_ref` is `None`,
/// evaluates whether the revocation activates without needing any seal.
fn check_active_revocation_role(
    rev_issuer: &str,
    rev_time: &UtcInstant,
    rev_ref: &str,
    target: &LinkNode,
    ancestors: &[&LinkNode],
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: Option<&BTreeMap<String, Vec<UtcInstant>>>,
) -> Option<EndingSignerKind> {
    // 1. Non-root `FromAbove` (issuer of a child link with `parent.is_some()`, or stand-in).
    let non_root_above = std::iter::once(target)
        .chain(ancestors.iter().copied())
        .any(|lnk| lnk.parent.is_some() && succ.stands_in_for(rev_issuer, &lnk.issuer, rev_time));
    if non_root_above
        && non_root_satisfies_handover_rule(rev_issuer, rev_ref, succ, shown_times_by_ref)
    {
        return Some(EndingSignerKind::FromAbove);
    }

    // 2. Root `FromAbove` (`A6` Slice 2 §4.3.2): carried links reach a deployment-root `L0`.
    if target_reaches_deployment_root(target, ancestors, tenures) {
        match evaluate_root_tenure(tenures, rev_issuer, rev_time) {
            RootTenureMatch::Open => return Some(EndingSignerKind::FromAbove),
            RootTenureMatch::Closed { end_time, .. } => {
                if shown_times_by_ref
                    .and_then(|m| m.get(rev_ref))
                    .is_some_and(|seals| seals.iter().any(|s| s < &end_time))
                {
                    return Some(EndingSignerKind::FromAbove);
                }
            }
            RootTenureMatch::NoTenure | RootTenureMatch::PredatesAdmission => {}
        }
    }

    // 3. Non-root `SelfKey` (`target.subject` or stand-in).
    if succ.stands_in_for(rev_issuer, &target.subject, rev_time)
        && non_root_satisfies_handover_rule(rev_issuer, rev_ref, succ, shown_times_by_ref)
    {
        return Some(EndingSignerKind::SelfKey);
    }

    None
}

/// §6: Compares a single step `step` against a single touching ending `ending`
/// (`A6` Slice 2 §4.1 withdraws the unsealed root-succession clock bypass).
fn compare_step_with_ending(
    step: &StepInfo<'_>,
    ending: &ApplicableEnding,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> EndingComparison {
    let t = step.captured_at;
    let e = &ending.captured_at;

    let step_seals = shown_times_by_ref
        .get(step.rec_ref)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    match ending.signer_kind {
        EndingSignerKind::FromAbove => {
            if step_seals.iter().any(|s| s < e) {
                EndingComparison::ShownToPrecede
            } else if t >= e {
                EndingComparison::Applies
            } else {
                EndingComparison::SignersClock
            }
        }
        EndingSignerKind::SelfKey => {
            let ending_seals = shown_times_by_ref
                .get(&ending.rec_ref)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let is_first = |s: &UtcInstant| !ending_seals.iter().any(|s_e| s_e <= s);

            if step_seals.iter().any(|s| is_first(s) && s < e) {
                EndingComparison::ShownToPrecede
            } else if t >= e && !step_seals.iter().any(is_first) {
                EndingComparison::Applies
            } else {
                EndingComparison::SignersClock
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainEndingVerdict {
    /// Row 1: no ending touches, or every touching comparison is `ShownToPrecede`.
    Ok,
    /// Row 2: no comparison `Applies`, and at least one is `SignersClock` (lowest ending ref).
    SignersClock(String),
    /// Row 4: at least one comparison `Applies` (lowest applying ending ref).
    Applies(String),
}

fn step_info_for_link<'a>(link: &'a LinkNode, tenures: &[RootTenure]) -> StepInfo<'a> {
    if link.parent.is_none() {
        let root_ending = match evaluate_root_tenure(tenures, &link.issuer, &link.captured_at) {
            RootTenureMatch::Closed { end_ref, end_time } => Some(ApplicableEnding {
                rec_ref: end_ref,
                captured_at: end_time,
                signer_kind: EndingSignerKind::FromAbove,
            }),
            _ => None,
        };
        StepInfo {
            rec_ref: &link.rec_ref,
            issuer: &link.issuer,
            captured_at: &link.captured_at,
            is_root_step: true,
            root_ending,
        }
    } else {
        StepInfo {
            rec_ref: &link.rec_ref,
            issuer: &link.issuer,
            captured_at: &link.captured_at,
            is_root_step: false,
            root_ending: None,
        }
    }
}

/// Evaluates all touching endings across steps `[links_before_final..., final_step]`:
/// - `Revocation` on `Lk` (`0 <= k < links_before_final.len()`) compared with subsequent steps;
/// - `RootsChanged` ending (`T_latest.ended_by`) on any root step (`L0`);
/// - `Succession` endings on any non-root step (`A6` Slice 2 §4.1).
fn evaluate_steps_against_endings(
    links_before_final: &[&LinkNode],
    final_step: &StepInfo<'_>,
    entitled_revocations_by_target: &BTreeMap<String, Vec<ApplicableEnding>>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> ChainEndingVerdict {
    let mut steps: Vec<StepInfo<'_>> = Vec::with_capacity(links_before_final.len() + 1);
    for l in links_before_final {
        steps.push(step_info_for_link(l, tenures));
    }
    steps.push(final_step.clone());

    let mut min_applies: Option<String> = None;
    let mut min_clock: Option<String> = None;

    let mut record_cmp = |cmp: EndingComparison, ending_ref: &str| match cmp {
        EndingComparison::ShownToPrecede => {}
        EndingComparison::SignersClock => {
            if min_clock
                .as_ref()
                .is_none_or(|cur| ending_ref.as_bytes() < cur.as_bytes())
            {
                min_clock = Some(ending_ref.to_string());
            }
        }
        EndingComparison::Applies => {
            if min_applies
                .as_ref()
                .is_none_or(|cur| ending_ref.as_bytes() < cur.as_bytes())
            {
                min_applies = Some(ending_ref.to_string());
            }
        }
    };

    // 1. Revocation of `Lk` (`0 <= k < links_before_final.len()`) compared with every step after `Lk`.
    for (k, link_k) in links_before_final.iter().enumerate() {
        if let Some(revs) = entitled_revocations_by_target.get(&link_k.rec_ref) {
            for rev_end in revs {
                for step_after in &steps[(k + 1)..] {
                    let cmp = compare_step_with_ending(step_after, rev_end, shown_times_by_ref);
                    record_cmp(cmp, &rev_end.rec_ref);
                }
            }
        }
    }

    // 2. Root-tenure endings (`RootsChanged`) on root steps, and `Succession` endings on non-root steps.
    for step in &steps {
        if step.is_root_step {
            if let Some(re) = &step.root_ending {
                let cmp = compare_step_with_ending(step, re, shown_times_by_ref);
                record_cmp(cmp, &re.rec_ref);
            }
        } else {
            for succ_end in succ.succession_endings_for_key(step.issuer) {
                let cmp = compare_step_with_ending(step, &succ_end, shown_times_by_ref);
                record_cmp(cmp, &succ_end.rec_ref);
            }
        }
    }

    if let Some(end_ref) = min_applies {
        ChainEndingVerdict::Applies(end_ref)
    } else if let Some(end_ref) = min_clock {
        ChainEndingVerdict::SignersClock(end_ref)
    } else {
        ChainEndingVerdict::Ok
    }
}

/// §6 Condition 3 / `A6` Slice 2 §4.4 for corroborating seals:
/// 1. `seal_rec` has a valid chain `C1` covering `seal_rec` at `seal_time` with no active
///    `Revocation` on `C1` and no non-root `Succession` on `C1[1..]` or `seal_rec.issuer`; AND
/// 2. Either `C1[0]`'s matching root tenure is open (`ended_by == None`), OR `seal_rec.issuer`
///    also holds an unbroken `EpochSeal` chain `C2` covering `seal_rec.body.stream` (for some
///    window) anchored at an open root tenure (`ended_by == None`) with no active `Revocation`
///    on `C2` and no non-root `Succession` on `C2[1..]` or `seal_rec.issuer`.
fn seal_has_unconditional_standing(
    seal_rec: &OpenedRecord,
    seal_time: &UtcInstant,
    valid_links: &BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    entitled_revocations_by_target: &BTreeMap<String, Vec<ApplicableEnding>>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
) -> bool {
    let seal_issuer = seal_rec.signers[0].as_str();
    if !succ.succession_endings_for_key(seal_issuer).is_empty() {
        return false;
    }

    let chain_is_unrevoked_and_unhanded_over = |chain: &[&LinkNode]| -> bool {
        if chain.iter().any(|m| {
            entitled_revocations_by_target
                .get(&m.rec_ref)
                .is_some_and(|v| !v.is_empty())
        }) {
            return false;
        }
        chain[1..]
            .iter()
            .all(|m| succ.succession_endings_for_key(&m.issuer).is_empty())
    };

    let mut found_closed_c1 = false;

    for link in valid_links.values() {
        let subj_matches = if link.is_badge {
            link.subject == seal_issuer
        } else {
            succ.stands_in_for(seal_issuer, &link.subject, seal_time)
        };
        if !subj_matches {
            continue;
        }
        let LineageWalk::FullCandidate(chain) = walk_lineage(
            link,
            valid_links,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            tenures,
            succ,
            Some((seal_rec, seal_time)),
        ) else {
            continue;
        };

        if !chain_is_unrevoked_and_unhanded_over(&chain) {
            continue;
        }

        match evaluate_root_tenure(tenures, &chain[0].issuer, &chain[0].captured_at) {
            RootTenureMatch::Open => return true,
            RootTenureMatch::Closed { .. } => {
                found_closed_c1 = true;
            }
            RootTenureMatch::NoTenure | RootTenureMatch::PredatesAdmission => {}
        }
    }

    if !found_closed_c1 {
        return false;
    }

    // Check for `C2` covering `seal_rec.body.stream` for some window under an open root tenure (§4.4).
    for link in valid_links.values() {
        let subj_matches = if link.is_badge {
            link.subject == seal_issuer
        } else {
            succ.stands_in_for(seal_issuer, &link.subject, &link.not_after)
        };
        if !subj_matches || !link_covers_seal_for_some_window(link, seal_rec) {
            continue;
        }
        let LineageWalk::FullCandidate(c2) = walk_lineage(
            link,
            valid_links,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            tenures,
            succ,
            None,
        ) else {
            continue;
        };

        if !matches!(
            evaluate_root_tenure(tenures, &c2[0].issuer, &c2[0].captured_at),
            RootTenureMatch::Open
        ) {
            continue;
        }

        if chain_is_unrevoked_and_unhanded_over(&c2) {
            return true;
        }
    }

    false
}

/// §5 Row 5 check (`A6` Slice 2 §4.1): returns true if NO valid link names `issuer` (or a key
/// `issuer` stands in for at `rec_time`, for `Endorsement` links) as its subject, AND `issuer`
/// holds no root tenure.
fn has_no_standing(
    issuer: &str,
    rec_time: Option<&UtcInstant>,
    valid_links: &BTreeMap<String, LinkNode>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
) -> bool {
    if has_any_root_tenure(tenures, issuer) {
        return false;
    }
    for link in valid_links.values() {
        if link.subject == issuer {
            return false;
        }
        if !link.is_badge
            && let Some(t) = rec_time
            && succ.stands_in_for(issuer, &link.subject, t)
        {
            return false;
        }
    }
    true
}

fn collect_authority_records(
    opened_records: &[OpenedRecord],
    body_result_by_idx: &[String],
) -> (
    BTreeMap<String, LinkNode>,
    SuccessionIndex,
    Vec<RevocationRecord>,
) {
    let mut valid_links: BTreeMap<String, LinkNode> = BTreeMap::new();
    let mut succession_edges: Vec<SuccessionEdge> = Vec::new();
    let mut auth_revocations: Vec<RevocationRecord> = Vec::new();

    for (idx, rec) in opened_records.iter().enumerate() {
        if !rec.all_sigs_ok || body_result_by_idx[idx] != "ok" {
            continue;
        }
        match rec.kind_path().as_deref() {
            Some(KIND_ENDORSEMENT | KIND_BADGE) => {
                if let Some(node) = parse_link_node(rec)
                    && node.issuer != node.subject
                {
                    valid_links.insert(rec.rec_ref.clone(), node);
                }
            }
            Some(KIND_SUCCESSION) => {
                if let (Some(cap_str), Some(pred), Some(succ_kid)) = (
                    rec.payload.get("capturedAt").and_then(Value::as_str),
                    rec.payload
                        .get("body")
                        .and_then(|b| b.get("predecessor"))
                        .and_then(Value::as_str),
                    rec.payload
                        .get("body")
                        .and_then(|b| b.get("successor"))
                        .and_then(Value::as_str),
                ) && let Some(captured_at) = parse_rfc3339_instant(cap_str, None, false)
                {
                    succession_edges.push(SuccessionEdge {
                        rec_ref: rec.rec_ref.clone(),
                        predecessor: pred.to_string(),
                        successor: succ_kid.to_string(),
                        captured_at,
                    });
                }
            }
            Some(KIND_REVOCATION) => {
                if let (Some(cap_str), Some(target)) = (
                    rec.payload.get("capturedAt").and_then(Value::as_str),
                    rec.payload
                        .get("body")
                        .and_then(|b| b.get("target"))
                        .and_then(Value::as_str),
                ) && let Some(captured_at) = parse_rfc3339_instant(cap_str, None, false)
                {
                    auth_revocations.push(RevocationRecord {
                        rec_ref: rec.rec_ref.clone(),
                        issuer: rec.signers[0].clone(),
                        captured_at,
                        target: target.to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    (
        valid_links,
        SuccessionIndex::build(succession_edges),
        auth_revocations,
    )
}

type RevocationsAndSeals<'a> = (
    BTreeMap<String, TargetLineage<'a>>,
    BTreeSet<usize>,
    BTreeMap<String, Vec<ApplicableEnding>>,
    BTreeMap<String, Vec<UtcInstant>>,
);

fn solve_revocations_and_seals<'a>(
    valid_links: &'a BTreeMap<String, LinkNode>,
    succ: &SuccessionIndex,
    auth_revocations: &[RevocationRecord],
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    tenures: &[RootTenure],
) -> RevocationsAndSeals<'a> {
    let mut target_lineages: BTreeMap<String, TargetLineage<'a>> = BTreeMap::new();
    for link in valid_links.values() {
        target_lineages.insert(
            link.rec_ref.clone(),
            inspect_target_lineage(
                link,
                valid_links,
                opened_records,
                opened_by_ref,
                any_sig_failed_by_idx,
                body_result_by_idx,
                succ,
            ),
        );
    }

    let build_rev_map = |active_indices: &BTreeSet<usize>,
                         shown_opt: Option<&BTreeMap<String, Vec<UtcInstant>>>|
     -> BTreeMap<String, Vec<ApplicableEnding>> {
        let mut map: BTreeMap<String, Vec<ApplicableEnding>> = BTreeMap::new();
        for &idx in active_indices {
            let rev = &auth_revocations[idx];
            if let Some(target_link) = valid_links.get(&rev.target) {
                let ancs = target_lineages
                    .get(&rev.target)
                    .map(|tl| tl.ancestors.as_slice())
                    .unwrap_or(&[]);
                if let Some(signer_kind) = check_active_revocation_role(
                    &rev.issuer,
                    &rev.captured_at,
                    &rev.rec_ref,
                    target_link,
                    ancs,
                    tenures,
                    succ,
                    shown_opt,
                ) {
                    map.entry(rev.target.clone())
                        .or_default()
                        .push(ApplicableEnding {
                            rec_ref: rev.rec_ref.clone(),
                            captured_at: rev.captured_at.clone(),
                            signer_kind,
                        });
                }
            }
        }
        map
    };

    let compute_shown_times =
        |rev_map: &BTreeMap<String, Vec<ApplicableEnding>>| -> BTreeMap<String, Vec<UtcInstant>> {
            let mut shown: BTreeMap<String, Vec<UtcInstant>> = BTreeMap::new();
            for (seal_ref, covered_refs) in seal_covered_records {
                if covered_refs.is_empty() {
                    continue;
                }
                let Some(&seal_idx) = opened_by_ref.get(seal_ref) else {
                    continue;
                };
                let seal_rec = &opened_records[seal_idx];
                if !seal_rec.all_sigs_ok || seal_rec.kind_path().as_deref() != Some(KIND_EPOCH_SEAL)
                {
                    continue;
                }
                let Some(seal_time) = seal_rec
                    .payload
                    .get("capturedAt")
                    .and_then(Value::as_str)
                    .and_then(|s| parse_rfc3339_instant(s, None, false))
                else {
                    continue;
                };
                if seal_has_unconditional_standing(
                    seal_rec,
                    &seal_time,
                    valid_links,
                    opened_records,
                    opened_by_ref,
                    any_sig_failed_by_idx,
                    body_result_by_idx,
                    rev_map,
                    tenures,
                    succ,
                ) {
                    for cov_ref in covered_refs {
                        shown
                            .entry(cov_ref.clone())
                            .or_default()
                            .push(seal_time.clone());
                    }
                }
            }
            shown
        };

    // Pass 1: activate revocations that need no seal.
    let mut active_rev_indices: BTreeSet<usize> = BTreeSet::new();
    for (idx, rev) in auth_revocations.iter().enumerate() {
        let Some(target_link) = valid_links.get(&rev.target) else {
            continue;
        };
        let ancs = target_lineages
            .get(&rev.target)
            .map(|tl| tl.ancestors.as_slice())
            .unwrap_or(&[]);
        if check_active_revocation_role(
            &rev.issuer,
            &rev.captured_at,
            &rev.rec_ref,
            target_link,
            ancs,
            tenures,
            succ,
            None,
        )
        .is_some()
        {
            active_rev_indices.insert(idx);
        }
    }

    // Pass 2: fixed-point activation for revocations requiring a pre-ending qualifying seal,
    // enforcing Condition 3 non-circularity.
    let mut last_shown = compute_shown_times(&build_rev_map(&active_rev_indices, None));
    loop {
        let mut newly_added = Vec::new();

        for (idx, rev) in auth_revocations.iter().enumerate() {
            if active_rev_indices.contains(&idx) {
                continue;
            }
            let Some(target_link) = valid_links.get(&rev.target) else {
                continue;
            };
            let ancs = target_lineages
                .get(&rev.target)
                .map(|tl| tl.ancestors.as_slice())
                .unwrap_or(&[]);
            if check_active_revocation_role(
                &rev.issuer,
                &rev.captured_at,
                &rev.rec_ref,
                target_link,
                ancs,
                tenures,
                succ,
                Some(&last_shown),
            )
            .is_none()
            {
                continue;
            }
            // Verify non-circularity (§6 Condition 3): the revocation must still be covered by
            // qualifying seals whose standing survives once `idx` is active.
            let mut probe_indices = active_rev_indices.clone();
            probe_indices.insert(idx);
            let probe_shown =
                compute_shown_times(&build_rev_map(&probe_indices, Some(&last_shown)));
            if check_active_revocation_role(
                &rev.issuer,
                &rev.captured_at,
                &rev.rec_ref,
                target_link,
                ancs,
                tenures,
                succ,
                Some(&probe_shown),
            )
            .is_some()
            {
                newly_added.push(idx);
            }
        }

        if newly_added.is_empty() {
            break;
        }
        active_rev_indices.extend(newly_added);
        last_shown = compute_shown_times(&build_rev_map(&active_rev_indices, Some(&last_shown)));
    }

    let entitled_revocations_by_target = build_rev_map(&active_rev_indices, Some(&last_shown));
    let shown_times_by_ref = compute_shown_times(&entitled_revocations_by_target);

    (
        target_lineages,
        active_rev_indices,
        entitled_revocations_by_target,
        shown_times_by_ref,
    )
}

/// Computes qualifying seal timestamps (`rec_ref -> [seal.capturedAt]`) under a given open root
/// set (`P.body.roots[*].key`), used by `A6` Slice 2 §3.5 pre-change custodian endorsement sealing.
pub(crate) fn compute_qualifying_shown_times_for_roots(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    prior_roots: &BTreeSet<String>,
) -> BTreeMap<String, Vec<UtcInstant>> {
    let tenures: Vec<RootTenure> = prior_roots
        .iter()
        .map(|k| RootTenure {
            key: k.clone(),
            admitted_at: None,
            ended_by: None,
        })
        .collect();
    let (valid_links, succ, auth_revocations) =
        collect_authority_records(opened_records, body_result_by_idx);
    let (_, _, _, shown_times_by_ref) = solve_revocations_and_seals(
        &valid_links,
        &succ,
        &auth_revocations,
        opened_records,
        opened_by_ref,
        any_sig_failed_by_idx,
        body_result_by_idx,
        seal_covered_records,
        &tenures,
    );
    shown_times_by_ref
}

/// Computes `VERIFY-V2.md` §6.3a / Amendment A5 / Amendment A6 Slice 2 / Amendment A7 §3
/// `authority` findings for all opened records other than exempt kinds (`Principal`, `Succession`,
/// `DefinitionPublished`, `ChainStarted`, `Deployment`, `RootsChanged`, `RootChangeApproval`),
/// marks `authority_ok_by_idx` for records whose `authority` finding is `"ok"`, and returns the
/// set of `EpochSeal` references satisfying `A7` §4.6 under `tenures`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_authority_findings(
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    multi_sig_mismatch_by_idx: &[bool],
    seal_covered_records: &BTreeMap<String, BTreeSet<String>>,
    tenures: &[RootTenure],
    authority_ok_by_idx: &mut [bool],
    findings: &mut Vec<Finding>,
) -> BTreeSet<String> {
    let (valid_links, succ, auth_revocations) =
        collect_authority_records(opened_records, body_result_by_idx);
    let (target_lineages, active_rev_indices, entitled_revocations_by_target, shown_times_by_ref) =
        solve_revocations_and_seals(
            &valid_links,
            &succ,
            &auth_revocations,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            seal_covered_records,
            tenures,
        );
    let auth_rev_refs: BTreeSet<String> =
        auth_revocations.iter().map(|r| r.rec_ref.clone()).collect();
    let active_rev_refs: BTreeSet<String> = active_rev_indices
        .iter()
        .map(|&i| auth_revocations[i].rec_ref.clone())
        .collect();

    for (rec_idx, rec) in opened_records.iter().enumerate() {
        let kind_path = rec.kind_path();
        if is_exempt_from_a5_authority(kind_path.as_deref()) {
            continue;
        }
        let finding = match kind_path.as_deref() {
            Some(KIND_ENDORSEMENT | KIND_BADGE) => evaluate_link_record(
                rec_idx,
                rec,
                &valid_links,
                opened_records,
                opened_by_ref,
                any_sig_failed_by_idx,
                body_result_by_idx,
                &entitled_revocations_by_target,
                tenures,
                &succ,
                &shown_times_by_ref,
            ),
            Some(KIND_REVOCATION) => evaluate_revocation_record(
                rec_idx,
                rec,
                opened_records,
                opened_by_ref,
                any_sig_failed_by_idx,
                body_result_by_idx,
                &valid_links,
                &target_lineages,
                &auth_rev_refs,
                &active_rev_refs,
                tenures,
                &succ,
                &shown_times_by_ref,
            ),
            _ => evaluate_ordinary_record(
                rec,
                multi_sig_mismatch_by_idx[rec_idx],
                &valid_links,
                opened_records,
                opened_by_ref,
                any_sig_failed_by_idx,
                body_result_by_idx,
                &entitled_revocations_by_target,
                tenures,
                &succ,
                &shown_times_by_ref,
            ),
        };
        if finding.result == "ok" {
            authority_ok_by_idx[rec_idx] = true;
        }
        findings.push(finding);
    }

    let mut qualifying_seal_refs = BTreeSet::new();
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
        let Some(seal_time) = seal_rec
            .payload
            .get("capturedAt")
            .and_then(Value::as_str)
            .and_then(|s| parse_rfc3339_instant(s, None, false))
        else {
            continue;
        };
        if seal_has_unconditional_standing(
            seal_rec,
            &seal_time,
            &valid_links,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            &entitled_revocations_by_target,
            tenures,
            &succ,
        ) {
            qualifying_seal_refs.insert(seal_ref.clone());
        }
    }
    qualifying_seal_refs
}

/// §4.4 Incomplete `trustedChain`: every opened record eligible for A5 gets
/// `authority: incomplete / chain_not_carried` with `about = trustedChain`.
pub(crate) fn emit_incomplete_chain_authority_findings(
    opened_records: &[OpenedRecord],
    trusted_chain: &str,
    findings: &mut Vec<Finding>,
) {
    for rec in opened_records {
        let kp = rec.kind_path();
        if is_exempt_from_a5_authority(kp.as_deref()) {
            continue;
        }
        findings.push(Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "incomplete",
            "chain_not_carried",
            Some(trusted_chain.to_string()),
        ));
    }
}

fn evaluate_link_record(
    rec_idx: usize,
    rec: &OpenedRecord,
    valid_links: &BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    entitled_revocations_by_target: &BTreeMap<String, Vec<ApplicableEnding>>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> Finding {
    if body_result_by_idx[rec_idx] != "ok" {
        return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
    }

    let issuer = rec.signers[0].as_str();
    let rec_time = rec
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false));
    let has_parent_field = rec
        .payload
        .get("body")
        .and_then(Value::as_object)
        .is_some_and(|b| b.contains_key("parent"));

    // Bullet 1: No `parent` (`A5` §5 + `A6` Slice 2 §4.3.1):
    if !has_parent_field {
        let subj = rec
            .payload
            .get("body")
            .and_then(|b| b.get("subject"))
            .and_then(Value::as_str);
        if subj == Some(issuer) {
            return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
        }
        if rec.kind_path().as_deref() != Some(KIND_ENDORSEMENT) {
            return Finding::new(
                2,
                &rec.rec_ref,
                "authority",
                "failed",
                "no_standing",
                Some(issuer.to_string()),
            );
        }
        let Some(t) = &rec_time else {
            return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
        };

        match evaluate_root_tenure(tenures, issuer, t) {
            RootTenureMatch::NoTenure => {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "failed",
                    "no_standing",
                    Some(issuer.to_string()),
                );
            }
            RootTenureMatch::PredatesAdmission => {
                return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
            }
            RootTenureMatch::Open => {
                return Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "ok",
                    "ok",
                    Some(issuer.to_string()),
                );
            }
            RootTenureMatch::Closed { end_ref, end_time } => {
                let self_step = StepInfo {
                    rec_ref: &rec.rec_ref,
                    issuer,
                    captured_at: t,
                    is_root_step: true,
                    root_ending: Some(ApplicableEnding {
                        rec_ref: end_ref,
                        captured_at: end_time,
                        signer_kind: EndingSignerKind::FromAbove,
                    }),
                };
                match evaluate_steps_against_endings(
                    &[],
                    &self_step,
                    entitled_revocations_by_target,
                    tenures,
                    succ,
                    shown_times_by_ref,
                ) {
                    ChainEndingVerdict::Ok => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "ok",
                            "ok",
                            Some(issuer.to_string()),
                        );
                    }
                    ChainEndingVerdict::SignersClock(er) => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "incomplete",
                            "time_rests_on_the_signer",
                            Some(er),
                        );
                    }
                    ChainEndingVerdict::Applies(er) => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "failed",
                            "ended",
                            Some(er),
                        );
                    }
                }
            }
        }
    }

    // Bullet 2: With `parent` — apply Rows 1–4, else `failed / not_covered / null` (`A5` §5).
    if let Some(this_node) = parse_link_node(rec) {
        let parent_ref = this_node
            .parent
            .clone()
            .expect("has_parent_field was checked");
        let final_step = StepInfo {
            rec_ref: &this_node.rec_ref,
            issuer: &this_node.issuer,
            captured_at: &this_node.captured_at,
            is_root_step: false,
            root_ending: None,
        };
        match walk_lineage(
            &this_node,
            valid_links,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            tenures,
            succ,
            None,
        ) {
            LineageWalk::FullCandidate(full_links) => {
                let parent_chain = &full_links[..full_links.len() - 1];
                match evaluate_steps_against_endings(
                    parent_chain,
                    &final_step,
                    entitled_revocations_by_target,
                    tenures,
                    succ,
                    shown_times_by_ref,
                ) {
                    ChainEndingVerdict::Ok => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "ok",
                            "ok",
                            Some(parent_ref),
                        );
                    }
                    ChainEndingVerdict::SignersClock(end_ref) => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "incomplete",
                            "time_rests_on_the_signer",
                            Some(end_ref),
                        );
                    }
                    ChainEndingVerdict::Applies(end_ref) => {
                        return Finding::new(
                            2,
                            &rec.rec_ref,
                            "authority",
                            "failed",
                            "ended",
                            Some(end_ref),
                        );
                    }
                }
            }
            LineageWalk::MissingParent {
                carried_links,
                missing_ref,
            } => {
                let carried_parents = &carried_links[..carried_links.len() - 1];
                let verdict = evaluate_steps_against_endings(
                    carried_parents,
                    &final_step,
                    entitled_revocations_by_target,
                    tenures,
                    succ,
                    shown_times_by_ref,
                );
                if !matches!(verdict, ChainEndingVerdict::Applies(_)) {
                    return Finding::new(
                        2,
                        &rec.rec_ref,
                        "authority",
                        "incomplete",
                        "chain_not_carried",
                        Some(missing_ref),
                    );
                }
            }
            LineageWalk::Invalid => {
                if !valid_links.contains_key(&parent_ref) {
                    return Finding::new(
                        2,
                        &rec.rec_ref,
                        "authority",
                        "failed",
                        "not_covered",
                        None,
                    );
                }
            }
        }
    }

    if has_no_standing(issuer, rec_time.as_ref(), valid_links, tenures, succ) {
        Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "failed",
            "no_standing",
            Some(issuer.to_string()),
        )
    } else {
        Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None)
    }
}

fn evaluate_revocation_record(
    rec_idx: usize,
    rec: &OpenedRecord,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    valid_links: &BTreeMap<String, LinkNode>,
    target_lineages: &BTreeMap<String, TargetLineage<'_>>,
    auth_rev_refs: &BTreeSet<String>,
    active_rev_refs: &BTreeSet<String>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> Finding {
    if body_result_by_idx[rec_idx] != "ok" {
        return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
    }

    let issuer = rec.signers[0].as_str();
    let Some(target) = rec
        .payload
        .get("body")
        .and_then(|b| b.get("target"))
        .and_then(Value::as_str)
    else {
        return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
    };

    let Some(rev_time) = rec
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false))
    else {
        return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
    };

    if let Some(target_link) = valid_links.get(target) {
        let lineage = target_lineages.get(target);
        let ancs = lineage.map(|tl| tl.ancestors.as_slice()).unwrap_or(&[]);

        // Row 1: `target` is authority-stating and the issuer is entitled (§6 + `A6` Slice 2 §4.3.2).
        let row1_entitled = if auth_rev_refs.contains(&rec.rec_ref) {
            active_rev_refs.contains(&rec.rec_ref)
        } else {
            check_active_revocation_role(
                issuer,
                &rev_time,
                &rec.rec_ref,
                target_link,
                ancs,
                tenures,
                succ,
                Some(shown_times_by_ref),
            )
            .is_some()
        };
        if row1_entitled {
            return Finding::new(
                2,
                &rec.rec_ref,
                "authority",
                "ok",
                "ok",
                Some(target.to_string()),
            );
        }

        // `A6` Slice 2 §4.3.2: a removed root `R_old` revoking a deployment grant without a
        // qualifying seal `< R_end.capturedAt` fails with `ended` (`rev_time >= end_time`) or
        // `incomplete / time_rests_on_the_signer` (`rev_time < end_time`).
        let root_match = evaluate_root_tenure(tenures, issuer, &rev_time);
        if target_reaches_deployment_root(target_link, ancs, tenures)
            && let RootTenureMatch::Closed { end_ref, end_time } = &root_match
        {
            return if rev_time >= *end_time {
                Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "failed",
                    "ended",
                    Some(end_ref.clone()),
                )
            } else {
                Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "incomplete",
                    "time_rests_on_the_signer",
                    Some(end_ref.clone()),
                )
            };
        }

        // Row 2: `target` is authority-stating, the issuer is not shown entitled by the carried
        // links, and the top carried link above `target` names a parent that might yet be a valid grant.
        let non_root_role = non_root_revocation_role(issuer, &rev_time, target_link, ancs, succ);
        let non_root_handover_ok =
            non_root_satisfies_handover_rule(issuer, &rec.rec_ref, succ, Some(shown_times_by_ref));
        let root_can_revoke_above = match &root_match {
            RootTenureMatch::Open => true,
            RootTenureMatch::Closed { end_time, .. } => shown_times_by_ref
                .get(&rec.rec_ref)
                .is_some_and(|seals| seals.iter().any(|s| s < end_time)),
            RootTenureMatch::NoTenure | RootTenureMatch::PredatesAdmission => false,
        };
        let can_be_entitled_above = root_can_revoke_above
            || (non_root_role.is_none()
                && non_root_handover_ok
                && matches!(root_match, RootTenureMatch::NoTenure));

        if can_be_entitled_above
            && let Some(missing_parent) = lineage.and_then(|tl| tl.missing_top_parent.as_ref())
        {
            return Finding::new(
                2,
                &rec.rec_ref,
                "authority",
                "incomplete",
                "chain_not_carried",
                Some(missing_parent.clone()),
            );
        }

        if let RootTenureMatch::Closed { end_ref, end_time } = &root_match
            && lineage
                .and_then(|tl| tl.missing_top_parent.as_ref())
                .is_some()
        {
            return if rev_time >= *end_time {
                Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "failed",
                    "ended",
                    Some(end_ref.clone()),
                )
            } else {
                Finding::new(
                    2,
                    &rec.rec_ref,
                    "authority",
                    "incomplete",
                    "time_rests_on_the_signer",
                    Some(end_ref.clone()),
                )
            };
        }

        // Row 3: `target` is authority-stating and neither.
        return Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "failed",
            "no_standing",
            Some(issuer.to_string()),
        );
    }

    // Row 4: `target` might yet be a valid grant.
    if might_yet_be_valid_grant(
        target,
        opened_records,
        opened_by_ref,
        any_sig_failed_by_idx,
        body_result_by_idx,
    ) {
        return Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "incomplete",
            "chain_not_carried",
            Some(target.to_string()),
        );
    }

    // Row 5: Otherwise (`target` is carried and is not a grant, or failed a check).
    Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_ordinary_record(
    rec: &OpenedRecord,
    multi_sig_mismatch: bool,
    valid_links: &BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    entitled_revocations_by_target: &BTreeMap<String, Vec<ApplicableEnding>>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> Finding {
    // `A7` §3.2 Step 1: Required signer count mismatch guard (`signatures = k > 1` and `len != k`).
    if multi_sig_mismatch {
        return Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None);
    }

    // `A7` §3.2 Steps 2 & 3: Evaluate each signer `S_1, ..., S_m` in order and combine
    // (`failed` > `incomplete` > `ok`, lowest signer index wins ties; all `ok` -> `about_1`).
    let mut first_failed: Option<Finding> = None;
    let mut first_incomplete: Option<Finding> = None;
    let mut first_ok: Option<Finding> = None;

    for signer_kid in &rec.signers {
        let f = evaluate_ordinary_record_for_signer(
            rec,
            signer_kid.as_str(),
            valid_links,
            opened_records,
            opened_by_ref,
            any_sig_failed_by_idx,
            body_result_by_idx,
            entitled_revocations_by_target,
            tenures,
            succ,
            shown_times_by_ref,
        );
        match f.result.as_str() {
            "failed" => {
                if first_failed.is_none() {
                    first_failed = Some(f);
                }
            }
            "incomplete" => {
                if first_incomplete.is_none() {
                    first_incomplete = Some(f);
                }
            }
            _ => {
                if first_ok.is_none() {
                    first_ok = Some(f);
                }
            }
        }
    }

    first_failed
        .or(first_incomplete)
        .or(first_ok)
        .unwrap_or_else(|| {
            Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None)
        })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_ordinary_record_for_signer(
    rec: &OpenedRecord,
    issuer: &str,
    valid_links: &BTreeMap<String, LinkNode>,
    opened_records: &[OpenedRecord],
    opened_by_ref: &BTreeMap<String, usize>,
    any_sig_failed_by_idx: &[bool],
    body_result_by_idx: &[String],
    entitled_revocations_by_target: &BTreeMap<String, Vec<ApplicableEnding>>,
    tenures: &[RootTenure],
    succ: &SuccessionIndex,
    shown_times_by_ref: &BTreeMap<String, Vec<UtcInstant>>,
) -> Finding {
    let rec_time_opt = rec
        .payload
        .get("capturedAt")
        .and_then(Value::as_str)
        .and_then(|s| parse_rfc3339_instant(s, None, false));

    let mut min_ok_last_link: Option<String> = None;
    let mut min_clock_ending: Option<String> = None;
    let mut min_missing_parent: Option<String> = None;
    let mut min_applied_ending: Option<String> = None;

    if let Some(rec_time) = &rec_time_opt {
        let final_step = StepInfo {
            rec_ref: &rec.rec_ref,
            issuer,
            captured_at: rec_time,
            is_root_step: false,
            root_ending: None,
        };

        for link in valid_links.values() {
            let subj_matches = if link.is_badge {
                link.subject == issuer
            } else {
                succ.stands_in_for(issuer, &link.subject, rec_time)
            };
            if !subj_matches {
                continue;
            }

            match walk_lineage(
                link,
                valid_links,
                opened_records,
                opened_by_ref,
                any_sig_failed_by_idx,
                body_result_by_idx,
                tenures,
                succ,
                Some((rec, rec_time)),
            ) {
                LineageWalk::FullCandidate(chain) => {
                    let last_ref = &chain.last().unwrap().rec_ref;
                    match evaluate_steps_against_endings(
                        &chain,
                        &final_step,
                        entitled_revocations_by_target,
                        tenures,
                        succ,
                        shown_times_by_ref,
                    ) {
                        ChainEndingVerdict::Ok => {
                            if min_ok_last_link
                                .as_ref()
                                .is_none_or(|cur| last_ref.as_bytes() < cur.as_bytes())
                            {
                                min_ok_last_link = Some(last_ref.clone());
                            }
                        }
                        ChainEndingVerdict::SignersClock(end_ref) => {
                            if min_clock_ending
                                .as_ref()
                                .is_none_or(|cur| end_ref.as_bytes() < cur.as_bytes())
                            {
                                min_clock_ending = Some(end_ref);
                            }
                        }
                        ChainEndingVerdict::Applies(end_ref) => {
                            if min_applied_ending
                                .as_ref()
                                .is_none_or(|cur| end_ref.as_bytes() < cur.as_bytes())
                            {
                                min_applied_ending = Some(end_ref);
                            }
                        }
                    }
                }
                LineageWalk::MissingParent {
                    carried_links,
                    missing_ref,
                } => {
                    let verdict = evaluate_steps_against_endings(
                        &carried_links,
                        &final_step,
                        entitled_revocations_by_target,
                        tenures,
                        succ,
                        shown_times_by_ref,
                    );
                    if !matches!(verdict, ChainEndingVerdict::Applies(_))
                        && min_missing_parent
                            .as_ref()
                            .is_none_or(|cur| missing_ref.as_bytes() < cur.as_bytes())
                    {
                        min_missing_parent = Some(missing_ref);
                    }
                }
                LineageWalk::Invalid => {}
            }
        }
    }

    // §5 Rows 1–6 in priority order.
    if let Some(last_ref) = min_ok_last_link {
        return Finding::new(2, &rec.rec_ref, "authority", "ok", "ok", Some(last_ref));
    }
    if let Some(end_ref) = min_clock_ending {
        return Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "incomplete",
            "time_rests_on_the_signer",
            Some(end_ref),
        );
    }
    if let Some(missing_ref) = min_missing_parent {
        return Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "incomplete",
            "chain_not_carried",
            Some(missing_ref),
        );
    }
    if let Some(end_ref) = min_applied_ending {
        return Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "failed",
            "ended",
            Some(end_ref),
        );
    }
    if has_no_standing(issuer, rec_time_opt.as_ref(), valid_links, tenures, succ) {
        Finding::new(
            2,
            &rec.rec_ref,
            "authority",
            "failed",
            "no_standing",
            Some(issuer.to_string()),
        )
    } else {
        Finding::new(2, &rec.rec_ref, "authority", "failed", "not_covered", None)
    }
}
