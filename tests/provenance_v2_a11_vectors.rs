use r5e_verify_rs::provenance_v2::{
    TrustedCheckpoint, VerifyOptions, verify_bundle_a11_bytes, verify_bundle_bytes,
    wasm_ffi::verify_v2_ffi_bytes,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn build_opts_from_case_meta(case_meta: &Value) -> VerifyOptions {
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
    if let Some(tcs) = case_meta
        .get("trustedCheckpoints")
        .and_then(Value::as_array)
    {
        for tc in tcs {
            if let (Some(seq), Some(r)) = (
                tc.get("seq").and_then(Value::as_u64),
                tc.get("ref").and_then(Value::as_str),
            ) {
                opts.trusted_checkpoints.push(TrustedCheckpoint {
                    seq,
                    rec_ref: r.to_string(),
                });
            }
        }
    }
    opts
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
        90,
        "expected exactly 90 Amendment A11 conformance vector directories"
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

        let opts = build_opts_from_case_meta(&case_meta);
        let mode = case_meta
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("a11");
        let expected_baseline_clean = expected_report["baselineClean"]
            .as_bool()
            .expect("expected baselineClean bool");
        let expected_verdict = expected_report["verdict"]
            .as_str()
            .expect("expected verdict");

        if mode == "baseline" {
            let base_report = verify_bundle_bytes(&bundle_bytes, &opts)
                .unwrap_or_else(|e| panic!("case {name}: baseline bundle failed to read: {e}"));
            let actual_clean =
                base_report.summary.failed == 0 && base_report.summary.incomplete == 0;
            let actual_verdict = if base_report.summary.failed > 0 {
                "failed"
            } else if base_report.summary.incomplete > 0 {
                "incomplete"
            } else {
                "ok"
            };
            if actual_clean != expected_baseline_clean || actual_verdict != expected_verdict {
                failures.push(format!(
                    "=== CASE {name} (mode=baseline): clean/verdict mismatch (actual=({actual_clean},{actual_verdict}), expected=({expected_baseline_clean},{expected_verdict})) ==="
                ));
            }
            if expected_verdict == "ok" {
                let a11_report = verify_bundle_a11_bytes(&bundle_bytes, &opts)
                    .unwrap_or_else(|e| panic!("case {name}: a11 bundle failed to read: {e}"));
                if a11_report.verdict != "ok" || !a11_report.a11_findings.is_empty() {
                    failures.push(format!(
                        "=== CASE {name}: baseline bundle under A11 entry expected ok + 0 A11 findings, got verdict={} findings={} ===",
                        a11_report.verdict,
                        a11_report.a11_findings.len()
                    ));
                }
            }
            continue;
        }

        let report = verify_bundle_a11_bytes(&bundle_bytes, &opts)
            .unwrap_or_else(|e| panic!("case {name}: bundle failed to read: {e}"));

        // 1. Check exact baselineClean (both failed == 0 and incomplete == 0).
        let actual_baseline_clean =
            report.baseline.summary.failed == 0 && report.baseline.summary.incomplete == 0;
        if actual_baseline_clean != expected_baseline_clean {
            let non_ok_baseline: Vec<_> = report
                .baseline
                .findings
                .iter()
                .filter(|f| f.result != "ok")
                .collect();
            failures.push(format!(
                "=== CASE {name}: baselineClean mismatch (actual={actual_baseline_clean}, expected={expected_baseline_clean}) ===\nNON-OK BASELINE:\n{}",
                serde_json::to_string_pretty(&non_ok_baseline).unwrap()
            ));
            continue;
        }

        // 2. Check overall verdict.
        if report.verdict != expected_verdict {
            failures.push(format!(
                "=== CASE {name}: verdict mismatch (actual={}, expected={}) ===\nA11 FINDINGS:\n{}",
                report.verdict,
                expected_verdict,
                serde_json::to_string_pretty(&report.a11_findings).unwrap()
            ));
            continue;
        }

        // 3. Check every expected A11 finding is present with exact fields (about, category,
        //    code, layer, result, subject), and zero unexpected non-ok A11 findings were emitted.
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

fn cli_args_for_case(case_dir: &std::path::Path) -> Vec<String> {
    let case_meta: Value =
        serde_json::from_slice(&fs::read(case_dir.join("case.json")).expect("read case.json"))
            .expect("parse case.json");
    let mut args = vec![case_dir.join("bundle.json").to_string_lossy().to_string()];
    if let Some(tps) = case_meta.get("trustedProfiles").and_then(Value::as_array) {
        for tp in tps {
            if let Some(s) = tp.as_str() {
                args.push("--trusted-profile".into());
                args.push(s.to_string());
            }
        }
    }
    if let Some(pubs) = case_meta.get("trustedPublishers").and_then(Value::as_array) {
        for p in pubs {
            if let Some(s) = p.as_str() {
                args.push("--trusted-publisher".into());
                args.push(s.to_string());
            }
        }
    }
    if let Some(roots) = case_meta.get("trustedRoots").and_then(Value::as_array) {
        for r in roots {
            if let Some(s) = r.as_str() {
                args.push("--trusted-root".into());
                args.push(s.to_string());
            }
        }
    }
    if let Some(tc) = case_meta.get("trustedChain").and_then(Value::as_str) {
        args.push("--trusted-chain".into());
        args.push(tc.to_string());
    }
    if let Some(tcs) = case_meta
        .get("trustedCheckpoints")
        .and_then(Value::as_array)
    {
        for tc in tcs {
            if let (Some(seq), Some(r)) = (
                tc.get("seq").and_then(Value::as_u64),
                tc.get("ref").and_then(Value::as_str),
            ) {
                args.push("--checkpoint".into());
                args.push(format!("{seq}={r}"));
            }
        }
    }
    args
}

#[test]
fn cli_and_wasm_enforce_a11_and_preserve_baseline_output() {
    let bin = env!("CARGO_BIN_EXE_recurse_verify");
    let cases_root = a11_cases_dir();

    // 1. A11 failure case via CLI must exit non-zero (1) and emit A11Report with verdict "failed".
    let fail_dir = cases_root.join("basis-person-one-signature-rejected");
    let fail_out = Command::new(bin)
        .args(cli_args_for_case(&fail_dir))
        .output()
        .expect("run recurse_verify on A11 failure case");
    assert_eq!(
        fail_out.status.code(),
        Some(1),
        "A11 failure must exit 1 via CLI, stderr={}",
        String::from_utf8_lossy(&fail_out.stderr)
    );
    let fail_json: Value = serde_json::from_slice(&fail_out.stdout).expect("parse CLI JSON");
    assert_eq!(fail_json["amendment"], "A11");
    assert_eq!(fail_json["verdict"], "failed");

    // 2. Reader-supplied --checkpoint pin via CLI catches stripped fork.
    let ckpt_dir = cases_root.join("checkpoint-trusted-pin-catches-stripped-fork-rejected");
    let ckpt_out = Command::new(bin)
        .args(cli_args_for_case(&ckpt_dir))
        .output()
        .expect("run recurse_verify with --checkpoint");
    assert_eq!(ckpt_out.status.code(), Some(1));
    let ckpt_json: Value = serde_json::from_slice(&ckpt_out.stdout).expect("parse CLI JSON");
    assert_eq!(ckpt_json["verdict"], "failed");

    // 3. Valid A11 case via CLI exits 0 with verdict "ok".
    let ok_dir = cases_root.join("basis-person-two-signatures-valid");
    let ok_out = Command::new(bin)
        .args(cli_args_for_case(&ok_dir))
        .output()
        .expect("run recurse_verify on valid A11 case");
    assert_eq!(ok_out.status.code(), Some(0));
    let ok_json: Value = serde_json::from_slice(&ok_out.stdout).expect("parse CLI JSON");
    assert_eq!(ok_json["amendment"], "A11");
    assert_eq!(ok_json["verdict"], "ok");

    // 4. Pre-A11 baseline bundle via CLI exits 0 and emits unchanged baseline report (no "amendment").
    let base_dir = cases_root.join("baseline-bundle-under-a11-entry-ok");
    let base_out = Command::new(bin)
        .args(cli_args_for_case(&base_dir))
        .output()
        .expect("run recurse_verify on baseline bundle");
    assert_eq!(base_out.status.code(), Some(0));
    let base_json: Value = serde_json::from_slice(&base_out.stdout).expect("parse CLI JSON");
    assert_eq!(base_json["format"], "r5e.provenance-verify-report/v2");
    assert!(base_json.get("amendment").is_none());
    assert_eq!(base_json["summary"]["failed"], 0);
    assert_eq!(base_json["summary"]["incomplete"], 0);

    // 5. WASM FFI enforces A11 on failure case and returns non-zero exitCode.
    let fail_meta: Value =
        serde_json::from_slice(&fs::read(fail_dir.join("case.json")).unwrap()).unwrap();
    let fail_bundle = fs::read(fail_dir.join("bundle.json")).unwrap();
    let wasm_opts = serde_json::to_vec(&json!({
        "trustedProfiles": fail_meta["trustedProfiles"],
        "trustedPublishers": fail_meta["trustedPublishers"],
        "trustedRoots": fail_meta["trustedRoots"],
    }))
    .unwrap();
    let wasm_out: Value =
        serde_json::from_slice(&verify_v2_ffi_bytes(&fail_bundle, &wasm_opts)).unwrap();
    assert_eq!(wasm_out["ok"], true);
    assert_eq!(wasm_out["sound"], false);
    assert_eq!(wasm_out["exitCode"], 1);
    assert_eq!(wasm_out["report"]["amendment"], "A11");
    assert_eq!(wasm_out["report"]["verdict"], "failed");
}
