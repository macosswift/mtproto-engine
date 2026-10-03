//! Triage of failure records from many clients: groups them into cases, ranks the cases by how many
//! reports they come from, replays the top ones on each engine and keeps the reproduced ones as
//! cases a later build is checked against.
//!
//! A saved case holds the records it was built from and, per engine, whether the failure reproduced,
//! under which explanation and with which seed: the explanation that reproduced it on that engine, or
//! for an engine that did not reproduce it the one that did on another engine. `--check` replays
//! every saved case the same way and compares: a case that reproduces where it is expected not to is
//! a regression, one that no longer reproduces where it is expected to is fixed (or flaky) and has
//! its `reproduces` set to false by whoever fixed it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::json::{self, Value};
use crate::replay::{self, CandidateResult, FailureRecord, ReplayCase};

pub struct TriageArgs {
    pub records: Vec<String>,
    pub binary: String,
    pub engines: Vec<String>,
    pub max_cases: usize,
    pub save: Option<String>,
    pub check: Option<String>,
    pub plan_only: bool,
}

impl TriageArgs {
    pub fn parse(arguments: &[String]) -> Self {
        let mut args = Self {
            records: Vec::new(),
            binary: String::new(),
            engines: vec!["rust".into(), "mtprotokit".into()],
            max_cases: 10,
            save: None,
            check: None,
            plan_only: false,
        };
        let mut iter = arguments.iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--records" => args.records.push(iter.next().cloned().expect("records path")),
                "--telegramcore" => args.binary = iter.next().cloned().expect("telegramcore path"),
                "--engines" => args.engines = iter.next().expect("engines").split(',').map(str::to_string).collect(),
                "--max-cases" => args.max_cases = iter.next().and_then(|v| v.parse().ok()).expect("max cases"),
                "--save" => args.save = iter.next().cloned(),
                "--check" => args.check = iter.next().cloned(),
                "--plan" => args.plan_only = true,
                other => panic!("unknown argument {other}"),
            }
        }
        assert!(!args.records.is_empty() || args.check.is_some(), "--records PATH or --check DIR");
        assert!(args.plan_only || !args.binary.is_empty(), "--telegramcore PATH");
        args
    }
}

/// Files under `path`: the file itself, or the `.json` and `.jsonl` files of a directory, sorted.
fn record_files(path: &str) -> Vec<PathBuf> {
    let path = Path::new(path);
    if !path.is_dir() {
        return vec![path.to_path_buf()];
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|file| file.extension().is_some_and(|extension| extension == "json" || extension == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// Every record under the given paths, each marked with its report or file.
pub fn load_all(paths: &[String]) -> Vec<FailureRecord> {
    let mut records = Vec::new();
    for path in paths {
        for file in record_files(path) {
            let source = file.display().to_string();
            if let Ok(text) = std::fs::read_to_string(&file) {
                records.extend(replay::load_records_from(&text, &source));
            }
        }
    }
    records
}

/// Cases that most reports share first, then the most records.
pub fn ranked(records: &[FailureRecord]) -> Vec<ReplayCase> {
    let mut all = replay::cases(records);
    all.sort_by(|lhs, rhs| {
        rhs.sources.len().cmp(&lhs.sources.len()).then(rhs.records.cmp(&lhs.records)).then(lhs.name.cmp(&rhs.name))
    });
    all
}

/// An explanation of a case and the seed it was replayed with.
#[derive(Debug, Clone, PartialEq)]
pub struct Trial {
    pub explanation: String,
    pub seed: u64,
}

/// The first explanation that reproduced the case on each engine, if any.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Verdict {
    pub reproduced: BTreeMap<String, Option<Trial>>,
}

impl Verdict {
    pub fn summary(&self) -> &'static str {
        let rust = self.reproduced.get("rust").is_some_and(Option::is_some);
        let mtprotokit = self.reproduced.get("mtprotokit").is_some_and(Option::is_some);
        match (rust, mtprotokit) {
            (true, false) => "Rust only",
            (false, true) => "MtProtoKit only",
            (true, true) => "both engines",
            (false, false) => "not reproduced",
        }
    }
}

/// Tries every explanation on every engine until each engine reproduced the case or none is left.
fn replay_case(case: &ReplayCase, case_index: usize, args: &TriageArgs) -> (Verdict, Vec<CandidateResult>) {
    let mut verdict = Verdict::default();
    let mut rows = Vec::new();
    for engine in &args.engines {
        verdict.reproduced.insert(engine.clone(), None);
    }
    for (candidate_index, faults) in replay::hypotheses(case).into_iter().enumerate() {
        let seed = 9000 + case_index as u64 * 101 + candidate_index as u64 * 7;
        for engine in &args.engines {
            if verdict.reproduced.get(engine).is_some_and(Option::is_some) {
                continue;
            }
            eprintln!("{} — {} — tc-{engine}", case.name, replay::faults_label(&faults));
            let row = replay::replay_once(case, &faults, engine, seed, &args.binary);
            eprintln!("{}", replay::markdown_row(&row));
            if row.reproduced {
                verdict.reproduced.insert(engine.clone(), Some(Trial { explanation: row.faults.clone(), seed }));
            }
            rows.push(row);
        }
        if verdict.reproduced.values().all(Option::is_some) {
            break;
        }
    }
    (verdict, rows)
}

fn slug(name: &str) -> String {
    name.trim_start_matches("replay/")
        .chars()
        .map(
            |character| {
                if character.is_ascii_alphanumeric() || character == '.' || character == '-' { character } else { '_' }
            },
        )
        .collect()
}

/// A case to keep: its records and, per engine, the outcome and the explanation and seed to check it
/// with. An engine that did not reproduce the case is checked under the explanation that reproduced
/// it on another engine (Rust's first), with the seed it was tried with then.
pub fn fixture(case: &ReplayCase, records: &[FailureRecord], verdict: &Verdict) -> Value {
    let shared = verdict
        .reproduced
        .get("rust")
        .cloned()
        .flatten()
        .or_else(|| verdict.reproduced.values().flatten().next().cloned());
    let expect = verdict
        .reproduced
        .iter()
        .filter_map(|(engine, reproduced)| {
            let trial = reproduced.clone().or_else(|| shared.clone())?;
            Some((
                engine.clone(),
                Value::Object(vec![
                    ("reproduces".into(), Value::Bool(reproduced.is_some())),
                    ("explanation".into(), Value::String(trial.explanation)),
                    ("seed".into(), Value::Number(trial.seed as f64)),
                ]),
            ))
        })
        .collect();
    let members: Vec<Value> = records
        .iter()
        .filter(|record| record_case_name(record) == case.name)
        .map(|record| record.raw.clone())
        .collect();
    Value::Object(vec![
        ("name".into(), Value::String(case.name.clone())),
        ("expect".into(), Value::Object(expect)),
        ("records".into(), Value::Array(members)),
    ])
}

fn record_case_name(record: &FailureRecord) -> String {
    format!("replay/{}/{}/{}/{}", record.failure, record.role, record.method, record.link_class())
}

pub fn run(args: TriageArgs) {
    if let Some(directory) = &args.check {
        let regressions = check(directory, &args);
        if regressions > 0 {
            std::process::exit(1);
        }
        return;
    }
    let records = load_all(&args.records);
    let all = ranked(&records);
    let reports: std::collections::BTreeSet<&str> = records.iter().map(|record| record.source.as_str()).collect();
    eprintln!("{} records from {} reports, {} cases", records.len(), reports.len(), all.len());
    let mut summary = String::from(
        "| Case | Reports | Records by engine | Engine dropped connections | Reproduced | Rust | MtProtoKit |\n|---|---|---|---|---|---|---|\n",
    );
    let mut details = String::new();
    for (case_index, case) in all.iter().take(args.max_cases).enumerate() {
        let by_engine = case
            .engine_records
            .iter()
            .map(|(engine, count)| format!("{engine} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let drops = if case.drops.is_empty() {
            "-".to_string()
        } else {
            case.drops.iter().map(|(reason, count)| format!("{reason} ×{count}")).collect::<Vec<_>>().join(", ")
        };
        details.push_str(&format!("\n### {}\n  reports: {}\n\n", replay::describe(case), case.sources.join(", ")));
        if args.plan_only {
            summary.push_str(&format!(
                "| `{}` | {} | {by_engine} | {drops} | (plan) | | |\n",
                case.name,
                case.sources.len()
            ));
            continue;
        }
        let (verdict, rows) = replay_case(case, case_index, &args);
        let cell = |engine: &str| match verdict.reproduced.get(engine) {
            Some(Some(trial)) => format!("yes ({})", trial.explanation),
            Some(None) => "no".to_string(),
            None => "-".to_string(),
        };
        summary.push_str(&format!(
            "| `{}` | {} | {by_engine} | {drops} | {} | {} | {} |\n",
            case.name,
            case.sources.len(),
            verdict.summary(),
            cell("rust"),
            cell("mtprotokit")
        ));
        details.push_str("| Explanation | Engine | Reproduced | Local failures | Done/Issued | Failed or hung | p50 ms | p99 ms | Conns |\n");
        details.push_str("|---|---|---|---|---|---|---|---|---|\n");
        for row in &rows {
            details.push_str(&replay::markdown_row(row));
            details.push('\n');
        }
        if let Some(directory) = &args.save
            && verdict.reproduced.values().any(Option::is_some)
        {
            if let Err(error) = std::fs::create_dir_all(directory) {
                eprintln!("cannot create {directory}: {error}");
            }
            let path = Path::new(directory).join(format!("{}.json", slug(&case.name)));
            if path.exists() {
                eprintln!("kept {} (already saved; its expectations may have been edited)", path.display());
            } else {
                match std::fs::write(&path, fixture(case, &records, &verdict).to_json()) {
                    Ok(()) => eprintln!("saved {}", path.display()),
                    Err(error) => eprintln!("cannot save {}: {error}", path.display()),
                }
            }
        }
    }
    println!("{summary}{details}");
}

/// Replays every saved case on each engine with that engine's explanation and seed and compares
/// with its expectations. Returns the number of regressions.
pub fn check(directory: &str, args: &TriageArgs) -> usize {
    let mut table = String::from("| Case | Engine | Expected | Now | Status |\n|---|---|---|---|---|\n");
    let mut regressions = 0;
    for file in record_files(directory) {
        let Some(value) = std::fs::read_to_string(&file).ok().and_then(|text| json::parse(text.trim())) else {
            table.push_str(&format!("| `{}` | | | | unreadable |\n", file.display()));
            continue;
        };
        let name = value.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let records = value.get("records").map(|records| replay::load_records(&records.to_json())).unwrap_or_default();
        let Some(case) = replay::cases(&records).into_iter().find(|case| case.name == name) else {
            table.push_str(&format!("| `{name}` | | | | records no longer form this case |\n"));
            continue;
        };
        let expectations: Vec<(String, bool, String, u64)> = match value.get("expect") {
            Some(Value::Object(entries)) => entries
                .iter()
                .filter(|(engine, _)| args.engines.contains(engine))
                .map(|(engine, expected)| {
                    (
                        engine.clone(),
                        matches!(expected.get("reproduces"), Some(Value::Bool(true))),
                        expected.get("explanation").and_then(Value::as_str).unwrap_or_default().to_string(),
                        expected.get("seed").and_then(Value::as_f64).unwrap_or(9000.0) as u64,
                    )
                })
                .collect(),
            _ => Vec::new(),
        };
        for (engine, expected, explanation, seed) in expectations {
            let Some(faults) =
                replay::hypotheses(&case).into_iter().find(|faults| replay::faults_label(faults) == explanation)
            else {
                table.push_str(&format!(
                    "| `{name}` | {engine} | | | explanation `{explanation}` no longer offered |\n"
                ));
                continue;
            };
            let row = replay::replay_once(&case, &faults, &engine, seed, &args.binary);
            let status = match (expected, row.reproduced) {
                (true, true) => "still reproduces",
                (false, false) => "ok",
                (true, false) => "no longer reproduces: fixed, or flaky",
                (false, true) => {
                    regressions += 1;
                    "REGRESSION"
                }
            };
            table.push_str(&format!(
                "| `{name}` | {engine} | {} | {} | {status} |\n",
                if expected { "reproduces" } else { "does not" },
                if row.reproduced { "reproduces" } else { "does not" }
            ));
        }
    }
    println!("{table}");
    regressions
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str = r#"{"app":"12.1","cellular":false,"code":0,"connection":[{"ago":20.0,"state":"online"}],"datacenter":2,"duration":61.2,"engine":"rust","error":"","expected_bytes":0,"failure":"stalled","flood_wait":0,"hour":1759993200,"latency_p50":0.08,"latency_p90":0.2,"latency_samples":64,"in_flight":32,"layer":214,"method":"messages.getHistory","request_bytes":64,"retries":0,"role":"main","schema":1,"sequence":7,"server_errors":0,"since_online":0,"system":"macos-15.4.0","uptime":900,"via_proxy":false}"#;

    fn chunk(report: &str, records: &[String]) -> String {
        format!(r#"{{"report_id":"{report}","offset":0,"records":[{}]}}"#, records.join(","))
    }

    #[test]
    fn records_are_split_by_link_and_ranked_by_how_many_reports_share_them() {
        let slow = RECORD
            .replace("\"latency_p50\":0.08", "\"latency_p50\":0.9")
            .replace("\"cellular\":false", "\"cellular\":true");
        let text = format!(
            "[{},{},{}]",
            chunk("a", &[RECORD.to_string(), RECORD.to_string()]),
            chunk("b", std::slice::from_ref(&slow)),
            chunk("c", &[slow])
        );
        let records = replay::load_records_from(&text, "file");
        assert_eq!(records.iter().map(|record| record.source.as_str()).collect::<Vec<_>>(), ["a", "a", "b", "c"]);
        let all = ranked(&records);
        assert_eq!(
            all.iter().map(|case| (case.name.as_str(), case.sources.len(), case.records)).collect::<Vec<_>>(),
            [
                ("replay/stalled/main/messages.getHistory/rtt≤1024ms-cellular", 2, 2),
                ("replay/stalled/main/messages.getHistory/rtt≤128ms", 1, 2),
            ],
            "two reports on a cellular link outrank one report with more records"
        );
        assert_eq!(all[0].engine_records.get("rust"), Some(&2));
    }

    #[test]
    fn a_saved_case_rebuilds_the_same_case_and_explanation() {
        let records = replay::load_records_from(&format!("[{RECORD},{RECORD}]"), "file");
        let case = replay::cases(&records).remove(0);
        let mut verdict = Verdict::default();
        verdict.reproduced.insert("mtprotokit".into(), Some(Trial { explanation: "network only".into(), seed: 9007 }));
        verdict.reproduced.insert("rust".into(), None);
        assert_eq!(verdict.summary(), "MtProtoKit only");
        let saved = fixture(&case, &records, &verdict).to_json();
        let value = json::parse(&saved).expect("saved case is JSON");
        assert_eq!(value.get("name").and_then(Value::as_str), Some(case.name.as_str()), "the name survives its ≤");
        let rust = value.get("expect").and_then(|expect| expect.get("rust")).expect("rust expectation");
        assert_eq!(rust.get("reproduces"), Some(&Value::Bool(false)));
        assert_eq!(rust.get("explanation").and_then(Value::as_str), Some("network only"));
        assert_eq!(rust.get("seed").and_then(Value::as_f64), Some(9007.0));
        let back = replay::load_records(&value.get("records").expect("records").to_json());
        assert_eq!(back.len(), 2);
        let rebuilt = replay::cases(&back).remove(0);
        assert_eq!(rebuilt.name, case.name);
        assert_eq!(rebuilt.profile.latency, case.profile.latency);
        assert!(replay::hypotheses(&rebuilt).iter().any(|faults| replay::faults_label(faults) == "network only"));
        assert_eq!(slug(&case.name), "stalled_main_messages.getHistory_rtt_128ms");
    }

    #[test]
    fn each_engine_keeps_the_explanation_and_seed_it_reproduced_with() {
        let records = replay::load_records_from(&format!("[{RECORD}]"), "file");
        let case = replay::cases(&records).remove(0);
        let mut verdict = Verdict::default();
        verdict.reproduced.insert("mtprotokit".into(), Some(Trial { explanation: "network only".into(), seed: 9000 }));
        verdict.reproduced.insert("rust".into(), Some(Trial { explanation: "flood 5%".into(), seed: 9014 }));
        let value = fixture(&case, &records, &verdict);
        let expect = value.get("expect").expect("expect");
        let trial = |engine: &str| {
            let entry = expect.get(engine).expect("engine");
            (
                entry.get("reproduces").cloned(),
                entry.get("explanation").and_then(Value::as_str).map(str::to_string),
                entry.get("seed").and_then(Value::as_f64),
            )
        };
        assert_eq!(trial("rust"), (Some(Value::Bool(true)), Some("flood 5%".into()), Some(9014.0)));
        assert_eq!(trial("mtprotokit"), (Some(Value::Bool(true)), Some("network only".into()), Some(9000.0)));
    }
}
