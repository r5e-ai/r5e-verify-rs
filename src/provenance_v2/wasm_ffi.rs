use super::{
    R5E_API_CHAIN_REF, R5E_API_PUBLISHER_PIN, TrustedCheckpoint, VerifyOptions,
    verify_bundle_auto_bytes,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmOptionsInput {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    trusted_profiles: Vec<String>,
    #[serde(default)]
    trusted_publishers: Vec<String>,
    #[serde(default)]
    publishers: Vec<String>,
    #[serde(default)]
    trusted_roots: Option<Vec<String>>,
    #[serde(default)]
    trusted_chain: Option<String>,
    #[serde(default)]
    min_start_seq: Option<i64>,
    #[serde(default)]
    trusted_checkpoints: Vec<TrustedCheckpoint>,
    #[serde(default)]
    installed_definitions: Vec<String>,
}

/// Pure byte-slice entrypoint shared by native tests and the `wasm32-unknown-unknown`
/// zero-import Audit Capsule module.
pub fn verify_v2_ffi_bytes(bundle_bytes: &[u8], opts_bytes: &[u8]) -> Vec<u8> {
    let mut opts = VerifyOptions::default();
    if !opts_bytes.is_empty() {
        match serde_json::from_slice::<WasmOptionsInput>(opts_bytes) {
            Ok(parsed) => {
                opts.trusted_profiles.extend(parsed.trusted_profiles);
                opts.trusted_publishers.extend(parsed.trusted_publishers);
                opts.trusted_publishers.extend(parsed.publishers);
                opts.trusted_roots = parsed
                    .trusted_roots
                    .map(|roots| roots.into_iter().collect());
                opts.trusted_chain = parsed.trusted_chain;
                if let Some(prof) = parsed.profile {
                    if prof != "r5e-api" {
                        return serde_json::to_vec(&json!({
                            "ok": false,
                            "exitCode": 2,
                            "error": format!("unknown --profile '{prof}' (supported: r5e-api)"),
                        }))
                        .unwrap_or_default();
                    }
                    if opts.trusted_roots.is_none() {
                        if opts.trusted_chain.is_some() {
                            return serde_json::to_vec(&json!({
                                "ok": false,
                                "exitCode": 2,
                                "error": "trustedChain may not be given more than once",
                            }))
                            .unwrap_or_default();
                        }
                        opts.trusted_chain = Some(R5E_API_CHAIN_REF.to_string());
                    }
                    opts.trusted_publishers
                        .insert(R5E_API_PUBLISHER_PIN.to_string());
                }
                if let Some(ms) = parsed.min_start_seq {
                    if !(2..=super::canonical::MAX_SAFE_INT).contains(&ms) {
                        return serde_json::to_vec(&json!({
                            "ok": false,
                            "exitCode": 2,
                            "error": "minStartSeq must be an integer >= 2",
                        }))
                        .unwrap_or_default();
                    }
                    opts.min_start_seq = Some(ms as u64);
                }
                opts.trusted_checkpoints = parsed.trusted_checkpoints;
                for def_str in parsed.installed_definitions {
                    opts.insert_installed_definition_bytes(def_str.into_bytes());
                }
            }
            Err(err) => {
                return serde_json::to_vec(&json!({
                    "ok": false,
                    "exitCode": 2,
                    "error": format!("invalid verifier options JSON: {err}"),
                }))
                .unwrap_or_default();
            }
        }
    }

    match verify_bundle_auto_bytes(bundle_bytes, &opts) {
        Ok(report) => {
            let canonical_json = report.to_canonical_json();
            serde_json::to_vec(&json!({
                "ok": true,
                "sound": report.is_sound(),
                "established": report.is_established(),
                "exitCode": report.exit_code(false),
                "report": report.to_value(),
                "canonicalReportJson": canonical_json,
            }))
            .unwrap_or_default()
        }
        Err(err) => serde_json::to_vec(&json!({
            "ok": false,
            "exitCode": 2,
            "error": err.0,
        }))
        .unwrap_or_default(),
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::verify_v2_ffi_bytes;
    use std::alloc::{Layout, alloc, dealloc};
    use std::ptr::NonNull;

    fn fail_closed_rng(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }

    getrandom::register_custom_getrandom!(fail_closed_rng);

    #[unsafe(no_mangle)]
    pub extern "C" fn r5e_alloc(len: usize) -> *mut u8 {
        if len == 0 {
            return NonNull::<u8>::dangling().as_ptr();
        }
        let Ok(layout) = Layout::from_size_align(len, 1) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `len > 0` and alignment is 1.
        unsafe { alloc(layout) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn r5e_dealloc(ptr: *mut u8, len: usize) {
        if len == 0 || ptr.is_null() {
            return;
        }
        if let Ok(layout) = Layout::from_size_align(len, 1) {
            // SAFETY: Caller passes pointer and exact length returned by `r5e_alloc`.
            unsafe { dealloc(ptr, layout) };
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn r5e_verify_v2_json(
        bundle_ptr: *const u8,
        bundle_len: usize,
        opts_ptr: *const u8,
        opts_len: usize,
    ) -> u64 {
        // SAFETY: Caller passes linear-memory slices allocated via `r5e_alloc` (or 0-length).
        let bundle = if bundle_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(bundle_ptr, bundle_len) }
        };
        let opts = if opts_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(opts_ptr, opts_len) }
        };

        let out = verify_v2_ffi_bytes(bundle, opts);
        let out_len = out.len();
        let out_ptr = r5e_alloc(out_len);
        if out_ptr.is_null() {
            return 0;
        }
        if out_len > 0 {
            // SAFETY: `out_ptr` points to `out_len` writable bytes disjoint from `out`.
            unsafe {
                std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, out_len);
            }
        }
        ((out_ptr as usize as u64) << 32) | (out_len as u64)
    }
}
