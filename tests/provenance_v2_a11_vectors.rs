use r5e_verify_rs::provenance_v2::{VerifyOptions, verify_bundle_a11_bytes};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn a11_cases_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("R5E_A11_VECTORS_DIR") {
        return PathBuf::from(dir).join("cases");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join("r5e-spec")
        .join("amendments")
        .join("a11")
        .join("cases")
}

#[test]
fn all_a11_conformance_vector_cases_match_expected_reports() {
    let cases_root = a11_cases_dir();
    let mut entries: Vec<_> = fs::read_dir(&cases_root)
        .expect("read amendments/a11/cases directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    assert_eq!(
        entries.len(),
        33,
        "expected exactly 33 Amendment A11 conformance vector directories"
    );

    let mut failures = Vec::new();
    for case_dir in &entries {
        let name = case_dir.file_name().unwrap().to_string_lossy().to_string();
        let case_meta: Value =
            serde_json::from_slice(&fs::read(case_dir.join("case.json")).expect("read case.json"))
                .expect("parse case.json");
        let bundle_bytes = fs::read(case_dir.join("bundle.json")).expect("read bundle.json");
        let expected_report: Value = serde_json::from_slice(
            &fs::read(case_dir.join("expected-report.json")).expect("read expected-report.json"),
        )
        .expect("parse expected-report.json");

        let mut opts = VerifyOptions::default();
        if let Some(tps) = case_meta.get("trustedProfiles").and_then(Value::as_array) {
            for tp in tps {
                if let Some(s) = tp.as_str() {
                    opts.trusted_profiles.insert(s.to_string());
                }
            }
        }
        if let Some(pubs) = case_meta.get("trustedPublishers").and_then(Value::as_array) {
            for p in pubs {
                if let Some(s) = p.as_str() {
                    opts.trusted_publishers.insert(s.to_string());
                }
            }
        }
        if let Some(roots) = case_meta.get("trustedRoots").and_then(Value::as_array) {
            let mut root_set = BTreeSet::new();
            for r in roots {
                if let Some(s) = r.as_str() {
                    root_set.insert(s.to_string());
                }
            }
            opts.trusted_roots = Some(root_set);
        }
        if let Some(tc) = case_meta.get("trustedChain").and_then(Value::as_str) {
            opts.trusted_chain = Some(tc.to_string());
        }
        if let Some(ms) = case_meta.get("minStartSeq").and_then(Value::as_u64) {
            opts.min_start_seq = Some(ms);
        }

        let report = verify_bundle_a11_bytes(&bundle_bytes, &opts)
            .unwrap_or_else(|e| panic!("case {name}: bundle failed to read: {e}"));

        // 1. Check baselineClean when expected.
        if expected_report
            .get("baselineClean")
            .and_then(Value::as_bool)
            == Some(true)
            && report.baseline.summary.failed > 0
        {
            let failed_baseline: Vec<_> = report
                .baseline
                .findings
                .iter()
                .filter(|f| f.result == "failed")
                .collect();
            failures.push(format!(
                "=== CASE {name}: baselineClean expected true, got {} baseline failures ===\n{}",
                report.baseline.summary.failed,
                serde_json::to_string_pretty(&failed_baseline).unwrap()
            ));
            continue;
        }

        // 2. Check overall verdict.
        let expected_verdict = expected_report["verdict"]
            .as_str()
            .expect("expected verdict");
        if report.verdict != expected_verdict {
            failures.push(format!(
                "=== CASE {name}: verdict mismatch (actual={}, expected={}) ===\nA11 FINDINGS:\n{}",
                report.verdict,
                expected_verdict,
                serde_json::to_string_pretty(&report.a11_findings).unwrap()
            ));
            continue;
        }

        // 3. Check every expected A11 finding is present with exact fields, and no unexpected
        //    non-ok A11 findings were emitted.
        let actual_values: Vec<Value> = report.a11_findings.iter().map(|f| f.to_value()).collect();
        let expected_findings = expected_report["expectedA11Findings"]
            .as_array()
            .expect("expectedA11Findings array");

        for exp in expected_findings {
            if !actual_values.contains(exp) {
                failures.push(format!(
                    "=== CASE {name}: missing expected A11 finding ===\nEXPECTED:\n{}\nACTUAL ALL:\n{}",
                    serde_json::to_string_pretty(exp).unwrap(),
                    serde_json::to_string_pretty(&actual_values).unwrap()
                ));
            }
        }

        for act in &actual_values {
            if act["result"] != "ok" && !expected_findings.contains(act) {
                failures.push(format!(
                    "=== CASE {name}: unexpected non-ok A11 finding ===\nUNEXPECTED:\n{}\nEXPECTED:\n{}",
                    serde_json::to_string_pretty(act).unwrap(),
                    serde_json::to_string_pretty(expected_findings).unwrap()
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} / {} A11 vector cases failed:\n{}",
            failures.len(),
            entries.len(),
            failures.join("\n")
        );
    }
}
