use serde_json::Value as V;
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
};

const USAGE: &str = "usage: recurse_verify [provenance] PATH_TO_BUNDLE.json\n                                     [--profile r5e-api]\n                                     [--trusted-profile REF]...\n                                     [--trusted-publisher KEYID[=DOMAINS] | --publisher KEYID[=DOMAINS]]...\n                                     [--trusted-root KEYID | --root KEYID]...\n                                     [--trusted-chain REF | --chain REF]\n                                     [--min-start-seq N]\n                                     [--establish-authority]\n                                     [--definitions-dir DIR]...\n                                     [--installed-definition PATH]...\n                                     [--report FILE]\n                                     [--allow-incomplete]";

#[derive(Debug, PartialEq, Eq)]
struct ParsedCliArgs {
    bundle_path: String,
    profiles: Vec<String>,
    trusted_profiles: Vec<String>,
    trusted_publishers: Vec<String>,
    trusted_roots: Vec<String>,
    trusted_chains: Vec<String>,
    min_start_seqs: Vec<String>,
    establish_authority: bool,
    definitions_dirs: Vec<String>,
    installed_def_files: Vec<String>,
    report_files: Vec<String>,
    allow_incomplete: bool,
}

fn parse_cli_args(args: &[String]) -> Result<ParsedCliArgs, String> {
    let mut profiles = vec![];
    let mut trusted_profiles = vec![];
    let mut trusted_publishers = vec![];
    let mut trusted_roots = vec![];
    let mut trusted_chains = vec![];
    let mut min_start_seqs = vec![];
    let mut establish_authority = false;
    let mut definitions_dirs = vec![];
    let mut installed_def_files = vec![];
    let mut report_files = vec![];
    let mut allow_incomplete = false;
    let mut pos = vec![];

    let v2_flags = [
        "--profile",
        "--trusted-profile",
        "--trusted-publisher",
        "--publisher",
        "--trusted-root",
        "--root",
        "--trusted-chain",
        "--chain",
        "--min-start-seq",
        "--definitions-dir",
        "--installed-definition",
        "--report",
    ];

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            if a == "--allow-incomplete" {
                allow_incomplete = true;
                i += 1;
                continue;
            }
            if a == "--establish-authority" {
                establish_authority = true;
                i += 1;
                continue;
            }
            if a.starts_with("--")
                && let Some((flag, eq_val)) = a.split_once('=')
            {
                if !v2_flags.contains(&flag) || eq_val.is_empty() {
                    return Err(USAGE.into());
                }
                let val = eq_val.to_string();
                match flag {
                    "--profile" => profiles.push(val),
                    "--trusted-profile" => trusted_profiles.push(val),
                    "--trusted-publisher" | "--publisher" => trusted_publishers.push(val),
                    "--trusted-root" | "--root" => trusted_roots.push(val),
                    "--trusted-chain" | "--chain" => trusted_chains.push(val),
                    "--min-start-seq" => min_start_seqs.push(val),
                    "--definitions-dir" => definitions_dirs.push(val),
                    "--installed-definition" => installed_def_files.push(val),
                    "--report" => report_files.push(val),
                    _ => unreachable!(),
                }
                i += 1;
                continue;
            }
            if !v2_flags.contains(&a.as_str()) || i + 1 >= args.len() || args[i + 1].starts_with("--") {
                return Err(USAGE.into());
            }
            i += 1;
            let val = args[i].clone();
            match a.as_str() {
                "--profile" => profiles.push(val),
                "--trusted-profile" => trusted_profiles.push(val),
                "--trusted-publisher" | "--publisher" => trusted_publishers.push(val),
                "--trusted-root" | "--root" => trusted_roots.push(val),
                "--trusted-chain" | "--chain" => trusted_chains.push(val),
                "--min-start-seq" => min_start_seqs.push(val),
                "--definitions-dir" => definitions_dirs.push(val),
                "--installed-definition" => installed_def_files.push(val),
                "--report" => report_files.push(val),
                _ => unreachable!(),
            }
        } else {
            pos.push(a.clone());
        }
        i += 1;
    }

    if pos.len() == 2 && pos[0] == "provenance" {
        pos.remove(0);
    }
    if pos.len() != 1 {
        return Err(USAGE.into());
    }

    Ok(ParsedCliArgs {
        bundle_path: pos.remove(0),
        profiles,
        trusted_profiles,
        trusted_publishers,
        trusted_roots,
        trusted_chains,
        min_start_seqs,
        establish_authority,
        definitions_dirs,
        installed_def_files,
        report_files,
        allow_incomplete,
    })
}

fn collect_json_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|_| format!("cannot read definitions directory {}", dir.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|_| format!("cannot read definitions directory {}", dir.display()))?;
        paths.push(entry.path());
    }
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect_json_files_recursive(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "json") {
            out.push(p);
        }
    }
    Ok(())
}

fn load_definitions_dir(
    dir_str: &str,
    v2_opts: &mut r5e_verify_rs::provenance_v2::VerifyOptions,
) -> Result<(), String> {
    let dir = Path::new(dir_str);
    if !dir.is_dir() {
        return Err(format!("no definitions directory at {dir_str}"));
    }
    let index_path = dir.join("index.json");
    if index_path.is_file() {
        let index_bytes = std::fs::read(&index_path)
            .map_err(|_| format!("cannot read {}", index_path.display()))?;
        let idx_val: V = r5e_verify_rs::provenance_v2::canonical::strict_json_parse(&index_bytes)
            .ok_or_else(|| format!("{} is not valid JSON", index_path.display()))?;
        let idx_map = idx_val
            .as_object()
            .ok_or_else(|| format!("{} must be an object", index_path.display()))?;
        let mut loaded_files: Vec<(String, Vec<u8>)> = Vec::with_capacity(idx_map.len());
        for kind_path in idx_map.keys() {
            let def_file = dir.join(format!("{kind_path}.json"));
            let def_bytes = std::fs::read(&def_file)
                .map_err(|_| format!("cannot read base definition {}", def_file.display()))?;
            loaded_files.push((kind_path.clone(), def_bytes));
        }
        let refs_slice: Vec<(&str, &[u8])> = loaded_files
            .iter()
            .map(|(k, b)| (k.as_str(), b.as_slice()))
            .collect();
        let base_defs = r5e_verify_rs::provenance_v2::BaseDefinitions::from_index_and_files(
            &index_bytes,
            &refs_slice,
        )
        .map_err(|e| e.to_string())?;
        v2_opts.base_definitions = Some(base_defs);
    }

    let mut all_json = Vec::new();
    collect_json_files_recursive(dir, &mut all_json)?;
    for jf in all_json {
        if jf == index_path {
            continue;
        }
        let bytes = std::fs::read(&jf).map_err(|_| format!("cannot read {}", jf.display()))?;
        v2_opts.insert_installed_definition_bytes(bytes);
    }
    Ok(())
}

fn run_provenance_v2(parsed: ParsedCliArgs) -> Result<i32, String> {
    let ParsedCliArgs {
        bundle_path,
        profiles,
        trusted_profiles,
        mut trusted_publishers,
        trusted_roots,
        mut trusted_chains,
        min_start_seqs,
        establish_authority,
        definitions_dirs,
        installed_def_files,
        report_files,
        allow_incomplete,
    } = parsed;

    if report_files.len() > 1 {
        return Err("--report may be given at most once".into());
    }
    let report_out = report_files.into_iter().next();

    if profiles.len() > 1 {
        return Err("--profile may be given at most once".into());
    }
    if let Some(prof) = profiles.into_iter().next() {
        if prof != "r5e-api" {
            return Err(format!("unknown --profile '{prof}' (supported: r5e-api)"));
        }
        if trusted_roots.is_empty() {
            trusted_chains.push(r5e_verify_rs::provenance_v2::R5E_API_CHAIN_REF.to_string());
        }
        trusted_publishers.push(r5e_verify_rs::provenance_v2::R5E_API_PUBLISHER_PIN.to_string());
    }
    let mut v2_opts = r5e_verify_rs::provenance_v2::VerifyOptions::default();
    for p in trusted_profiles {
        if p.is_empty() {
            return Err("--trusted-profile needs a reference".into());
        }
        v2_opts.trusted_profiles.insert(p);
    }
    for pub_spec in trusted_publishers {
        if pub_spec.is_empty() {
            return Err("--publisher needs a key id".into());
        }
        v2_opts
            .add_trusted_publisher(pub_spec)
            .map_err(|e| e.to_string())?;
    }
    if establish_authority || !trusted_roots.is_empty() {
        let mut roots = BTreeSet::new();
        for root_kid in trusted_roots {
            if root_kid.is_empty() {
                return Err("--trusted-root needs a key id".into());
            }
            roots.insert(root_kid);
        }
        v2_opts.trusted_roots = Some(roots);
    }
    if trusted_chains.len() > 1 {
        return Err("--trusted-chain may be given at most once".into());
    }
    if let Some(tc) = trusted_chains.into_iter().next() {
        if tc.is_empty() {
            return Err("--trusted-chain needs an evidence:sha256: reference".into());
        }
        v2_opts.trusted_chain = Some(tc);
    }
    if min_start_seqs.len() > 1 {
        return Err("--min-start-seq may be given at most once".into());
    }
    if let Some(raw_seq) = min_start_seqs.into_iter().next() {
        let parsed_seq = if !raw_seq.is_empty() && raw_seq.bytes().all(|b| b.is_ascii_digit()) {
            raw_seq.parse::<u64>().ok()
        } else {
            None
        };
        let Some(seq) = parsed_seq.filter(|&n| {
            (2..=r5e_verify_rs::provenance_v2::canonical::MAX_SAFE_INT as u64).contains(&n)
        }) else {
            return Err("--min-start-seq must be an integer >= 2".into());
        };
        v2_opts.min_start_seq = Some(seq);
    }
    v2_opts.validate().map_err(|e| e.to_string())?;
    for d in definitions_dirs {
        load_definitions_dir(&d, &mut v2_opts)?;
    }
    for f in installed_def_files {
        let bytes = std::fs::read(&f).map_err(|_| format!("cannot read definition file at {f}"))?;
        v2_opts.insert_installed_definition_bytes(bytes);
    }

    let bundle_bytes =
        std::fs::read(&bundle_path).map_err(|_| format!("cannot read bundle at {bundle_path}"))?;
    let report = r5e_verify_rs::provenance_v2::verify_bundle_bytes(&bundle_bytes, &v2_opts)
        .map_err(|e| format!("{bundle_path}: {e}"))?;
    let canonical = report.to_canonical_json();
    if let Some(ref out_path) = report_out {
        std::fs::write(out_path, canonical.as_bytes())
            .map_err(|e| format!("cannot write report file at {out_path}: {e}"))?;
    }
    std::io::stdout()
        .write_all(canonical.as_bytes())
        .map_err(|e| format!("stdout write error: {e}"))?;
    Ok(report.exit_code(allow_incomplete))
}

fn run() -> Result<i32, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let parsed = parse_cli_args(&args)?;
    run_provenance_v2(parsed)
}

fn main() {
    let code = match run() {
        Ok(c) => c,
        Err(s) => {
            if s == USAGE {
                eprintln!("{s}")
            } else {
                eprintln!("recurse_verify: {s}")
            }
            2
        }
    };
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn parses_direct_and_subcommand_provenance_flags() {
        let direct = parse_cli_args(&s(&[
            "bundle.json",
            "--profile=r5e-api",
            "--allow-incomplete",
        ]))
        .unwrap();
        assert_eq!(direct.bundle_path, "bundle.json");
        assert_eq!(direct.profiles, vec!["r5e-api"]);
        assert!(direct.allow_incomplete);

        let sub = parse_cli_args(&s(&[
            "provenance",
            "bundle.json",
            "--root",
            "key:ed25519:sha256:00",
            "--publisher=key:es256:sha256:11=r5e.io",
            "--establish-authority",
        ]))
        .unwrap();
        assert_eq!(sub.bundle_path, "bundle.json");
        assert_eq!(sub.trusted_roots, vec!["key:ed25519:sha256:00"]);
        assert_eq!(sub.trusted_publishers, vec!["key:es256:sha256:11=r5e.io"]);
        assert!(sub.establish_authority);
    }

    #[test]
    fn rejects_unknown_flags_or_missing_bundle_with_usage() {
        assert_eq!(parse_cli_args(&s(&[])), Err(USAGE.to_string()));
        assert_eq!(
            parse_cli_args(&s(&["bundle.json", "--unknown", "x"])),
            Err(USAGE.to_string())
        );
        assert_eq!(
            parse_cli_args(&s(&["bundle.json", "--chain="])),
            Err(USAGE.to_string())
        );
    }
}
