use r5e_verify_rs::provenance_v2::{VerifyOptions, verify_bundle_bytes};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn vectors_cases_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("R5E_PROVENANCE_VECTORS_DIR") {
        return PathBuf::from(dir).join("cases");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join("r5e-spec")
        .join("cases")
}

#[test]
fn all_provenance_v2_vector_cases_match_expected_reports() {
    let cases_root = vectors_cases_dir();
    let mut entries: Vec<_> = fs::read_dir(&cases_root)
        .expect("read provenance-vectors/cases directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    assert_eq!(
        entries.len(),
        162,
        "expected exactly 162 conformance vector directories"
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
            let mut root_set = std::collections::BTreeSet::new();
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

        let report = verify_bundle_bytes(&bundle_bytes, &opts)
            .unwrap_or_else(|e| panic!("case {name}: bundle failed to read: {e}"));
        let actual_val = report.to_value();

        // Verify canonical JSON round-trips to the exact report Value.
        let canonical_str = report.to_canonical_json();
        let reparsed: Value =
            serde_json::from_str(&canonical_str).expect("canonical report must parse as JSON");
        assert_eq!(reparsed, actual_val, "case {name}: canonical round-trip");

        if actual_val != expected_report {
            failures.push(format!(
                "=== CASE {name} MISMATCH ===\nACTUAL:\n{}\nEXPECTED:\n{}\n",
                serde_json::to_string_pretty(&actual_val).unwrap(),
                serde_json::to_string_pretty(&expected_report).unwrap()
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} / {} vector cases differed:\n{}",
            failures.len(),
            entries.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn r5e_api_block0_profile_is_strictly_opt_in_and_matches_canonical_report() {
    use r5e_verify_rs::provenance_v2::wasm_ffi::verify_v2_ffi_bytes;
    use sha2::{Digest, Sha256};
    use std::process::Command;

    let bin = env!("CARGO_BIN_EXE_recurse_verify");
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("genesis")
        .join("r5e-api")
        .join("block-0-r5e-api.json");
    let bundle_bytes = fs::read(&bundle_path).expect("read block-0-r5e-api.json");
    let expected_sha256 = "c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed";
    let root_key =
        "key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc";

    // 1. Default trust MUST remain empty (incomplete / publisher_not_trusted, exit 3).
    let out_default = Command::new(bin)
        .arg(&bundle_path)
        .output()
        .expect("run recurse_verify with default trust");
    assert_eq!(out_default.status.code(), Some(3));
    let rep_default: Value =
        serde_json::from_slice(&out_default.stdout).expect("parse default report");
    assert_eq!(rep_default["summary"]["failed"], 0);
    assert!(rep_default["summary"]["incomplete"].as_u64().unwrap() > 0);
    let has_untrusted_pub = rep_default["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["check"] == "publication" && f["code"] == "publisher_not_trusted");
    assert!(
        has_untrusted_pub,
        "default trust must not trust r5e.io publisher without --profile r5e-api"
    );

    // 2. Explicit `--profile r5e-api` and `--profile=r5e-api` produce 122/0/0 and exact canonical SHA-256.
    for flag_args in [&["--profile", "r5e-api"][..], &["--profile=r5e-api"][..]] {
        let out = Command::new(bin)
            .arg(&bundle_path)
            .args(flag_args)
            .output()
            .expect("run recurse_verify --profile r5e-api");
        assert_eq!(
            out.status.code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let canonical = out.stdout.strip_suffix(b"\n").unwrap_or(&out.stdout);
        let digest = format!("{:x}", Sha256::digest(canonical));
        assert_eq!(digest, expected_sha256);
        let rep: Value = serde_json::from_slice(canonical).unwrap();
        assert_eq!(rep["summary"]["ok"], 122);
        assert_eq!(rep["summary"]["failed"], 0);
        assert_eq!(rep["summary"]["incomplete"], 0);
    }

    // 3. `--profile r5e-api --root <root>` overrides `--chain` cleanly and matches exact canonical SHA-256.
    let out_root = Command::new(bin)
        .arg(&bundle_path)
        .args(["--profile", "r5e-api", "--root", root_key])
        .output()
        .expect("run recurse_verify --profile r5e-api --root");
    assert_eq!(out_root.status.code(), Some(0));
    let canonical_root = out_root
        .stdout
        .strip_suffix(b"\n")
        .unwrap_or(&out_root.stdout);
    assert_eq!(
        format!("{:x}", Sha256::digest(canonical_root)),
        expected_sha256
    );

    // 4. Unknown and duplicate `--profile` fail closed with exit 2.
    let out_bad = Command::new(bin)
        .arg(&bundle_path)
        .args(["--profile", "unknown"])
        .output()
        .unwrap();
    assert_eq!(out_bad.status.code(), Some(2));

    let out_dup = Command::new(bin)
        .arg(&bundle_path)
        .args(["--profile", "r5e-api", "--profile", "r5e-api"])
        .output()
        .unwrap();
    assert_eq!(out_dup.status.code(), Some(2));

    // 5. WASM FFI `{"profile":"r5e-api"}` matches exact canonical SHA-256 while `{}` stays incomplete.
    let ffi_default: Value =
        serde_json::from_slice(&verify_v2_ffi_bytes(&bundle_bytes, b"{}")).unwrap();
    assert_eq!(ffi_default["ok"], true);
    assert_eq!(ffi_default["established"], false);

    let ffi_prof: Value = serde_json::from_slice(&verify_v2_ffi_bytes(
        &bundle_bytes,
        br#"{"profile":"r5e-api"}"#,
    ))
    .unwrap();
    assert_eq!(ffi_prof["ok"], true);
    assert_eq!(ffi_prof["established"], true);
    let ffi_canon = ffi_prof["canonicalReportJson"].as_str().unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(ffi_canon.as_bytes())),
        expected_sha256
    );
}
