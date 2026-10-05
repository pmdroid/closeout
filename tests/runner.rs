use closeout::{
    changed_scope, evaluate, format_markdown, load_policy, read_evidence, resolve_commit, run_commands, seal_report, write_record,
    Candidate,
    Decision, DecisionName, EvaluateInput, EvidenceRecord, Gate, LoadResult, PolicyInfo, RunInput, SPEC_VERSION, VERSION,
};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct Expect {
    check: String,
    #[serde(default)]
    git: bool,
    ok: Option<bool>,
    message: Option<String>,
    #[serde(rename = "messageContains")]
    message_contains: Option<String>,
    #[serde(rename = "warningCodes")]
    warning_codes: Option<Vec<String>>,
    decision: Option<String>,
    candidate: Option<Candidate>,
    #[serde(default)]
    records: Vec<Value>,
    #[serde(default)]
    items: Vec<ExpectItem>,
    touch: Option<String>,
}

#[derive(Deserialize)]
struct ExpectItem {
    id: String,
    state: Option<String>,
    message: Option<String>,
}

#[test]
fn conformance_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance");
    let mut cases: Vec<_> = fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.is_dir()).collect();
    cases.sort();
    assert!(cases.len() >= 12, "missing conformance cases");
    for case in cases {
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        run_case(&name, &case);
    }
}

fn run_case(name: &str, case: &Path) {
    let expect: Expect = serde_json::from_str(&fs::read_to_string(case.join("expect.json")).unwrap()).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    copy_dir(&case.join("repo"), &repo);
    if expect.git {
        commit_repo(&repo);
    }
    let loaded = load_policy(&repo);
    match expect.check.as_str() {
        "validate" => check_validate(name, &expect, loaded),
        "digest" => check_digest(name, &expect, &repo, loaded),
        "decision" => check_decision(name, &expect, &repo, loaded),
        other => panic!("{name}: unknown check {other}"),
    }
}

fn check_validate(name: &str, expect: &Expect, loaded: LoadResult) {
    match loaded {
        LoadResult::Failed { message, .. } => {
            assert_eq!(expect.ok, Some(false), "{name} should fail validation");
            if let Some(exact) = &expect.message {
                assert_eq!(&message, exact, "{name}");
            }
            if let Some(part) = &expect.message_contains {
                assert!(message.contains(part), "{name}: {message}");
            }
        }
        LoadResult::Ready(policy) => {
            assert_eq!(expect.ok, Some(true), "{name} message should have been a failure");
            let _ = policy;
        }
    }
}

fn check_digest(name: &str, expect: &Expect, repo: &Path, loaded: LoadResult) {
    let LoadResult::Ready(before) = loaded else {
        panic!("{name}: policy did not load");
    };
    let touch = repo.join(expect.touch.as_deref().unwrap());
    let mut text = fs::read_to_string(&touch).unwrap();
    text.push('\n');
    fs::write(&touch, text).unwrap();
    let LoadResult::Ready(after) = load_policy(repo) else {
        panic!("{name}: policy did not reload");
    };
    assert_ne!(before.digest, after.digest, "{name}");
    assert!(before.digest.unwrap().starts_with("sha256:"));
}

fn check_decision(name: &str, expect: &Expect, repo: &Path, loaded: LoadResult) {
    let LoadResult::Ready(policy) = loaded else {
        panic!("{name}: policy did not load");
    };
    let head = resolve_commit(repo, "HEAD").unwrap_or_default();
    let base = head.clone();
    let digest = policy.digest.clone().unwrap_or_default();
    let evidence = repo.join(".closeout");
    for mut record in expect.records.clone() {
        substitute(&mut record, &base, &head, &digest);
        let typed: EvidenceRecord = serde_json::from_value(record).unwrap_or_else(|err| panic!("{name}: {err}"));
        write_record(&evidence, &typed).unwrap_or_else(|err| panic!("{name}: {err}"));
    }
    let records = read_evidence(&evidence).unwrap_or_else(|err| panic!("{name}: {err}"));
    let candidate = expect.candidate.clone().unwrap_or_default();
    let (scope, scope_error) = match changed_scope(repo, &policy, Gate::BeforePr, &base, &head) {
        Ok(paths) => (paths, None),
        Err(message) => (None, Some(message)),
    };
    let decision = evaluate(EvaluateInput {
        policy: &policy,
        gate: Gate::BeforePr,
        base: &base,
        head: &head,
        candidate: &candidate,
        records: &records,
        changed_paths: scope.as_deref(),
        evidence_error: scope_error,
    });
    assert_eq!(decision.decision.as_str(), expect.decision.as_deref().unwrap(), "{name}");
    if let Some(codes) = &expect.warning_codes {
        let actual: Vec<_> = decision.warnings.iter().map(|warning| warning.code.as_str()).collect();
        assert_eq!(&actual, codes, "{name}");
    }
    assert_eq!(decision.items.len(), expect.items.len(), "{name}");
    for (actual, expected) in decision.items.iter().zip(&expect.items) {
        assert_eq!(actual.id, expected.id, "{name}");
        if let Some(state) = &expected.state {
            assert_eq!(actual.state.as_str(), state, "{name} {}", actual.id);
        }
        if let Some(message) = &expected.message {
            assert_eq!(&actual.message, message, "{name} {}", actual.id);
        }
    }
}

fn substitute(value: &mut Value, base: &str, head: &str, digest: &str) {
    match value {
        Value::String(text) => {
            *text = text.replace("$digest", digest).replace("$base", base).replace("$head", head).replace("$version", VERSION);
        }
        Value::Array(items) => {
            for item in items {
                substitute(item, base, head, digest);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                substitute(child, base, head, digest);
            }
        }
        _ => {}
    }
}

#[test]
fn retry_limits_stop_execution_and_configure_commit_resets() {
    for scope in ["task", "candidate"] {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let counter = temp.path().join("attempts");
        fs::create_dir_all(repo.join(".agents")).unwrap();
        let policy = serde_json::json!({
            "specVersion": "0.1",
            "retry": { "maxFailedAttemptsPerItem": 2, "scope": scope },
            "items": [{
                "id": "check", "kind": "command", "gate": "beforePR",
                "exec": ["sh", "-c", "printf x >> \"$1\"; exit 1", "closeout", counter],
                "timeoutSeconds": 30
            }]
        });
        fs::write(repo.join(".agents/closeout.yaml"), policy.to_string()).unwrap();
        commit_repo(&repo);
        publish_origin(&repo);
        let base = resolve_commit(&repo, "HEAD").unwrap();
        let args = ["run", "--gate", "beforePR", "--base", &base, "--head", "HEAD", "--task", "task-one", "--json"];
        if scope == "task" {
            let missing_task = closeout(&repo, &["run", "--gate", "beforePR", "--base", &base, "--head", "HEAD", "--json"]);
            assert_eq!(missing_task.status.code(), Some(3));
            assert!(!counter.exists());
        }
        let first = closeout(&repo, &args);
        assert_eq!(first.status.code(), Some(1), "{}", String::from_utf8_lossy(&first.stdout));
        git(&repo, &["commit", "--allow-empty", "-m", "next candidate"]);
        let second = closeout(&repo, &args);
        assert_eq!(second.status.code(), Some(if scope == "task" { 3 } else { 1 }));
        let third = closeout(&repo, &args);
        assert_eq!(third.status.code(), Some(3));
        let decision: Value = serde_json::from_slice(&third.stdout).unwrap();
        assert_eq!(decision["items"][0]["state"], "exhausted");
        assert!(decision["items"][0]["message"].as_str().unwrap().contains("ask for help"));
        let fourth = closeout(&repo, &args);
        assert_eq!(fourth.status.code(), Some(3));
        assert_eq!(fs::read_to_string(&counter).unwrap().len(), if scope == "task" { 2 } else { 3 });
        if scope == "task" {
            let waiting = closeout(&repo, &["decision", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--task", "task-two", "--json"]);
            let waiting: Value = serde_json::from_slice(&waiting.stdout).unwrap();
            assert_eq!(waiting["items"][0]["state"], "missing");
            let next_task = closeout(&repo, &["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--task", "task-two", "--json"]);
            assert_eq!(next_task.status.code(), Some(1));
            assert_eq!(fs::read_to_string(&counter).unwrap().len(), 3);
            let still_exhausted = closeout(&repo, &["decision", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--task", "task-one", "--json"]);
            assert_eq!(still_exhausted.status.code(), Some(3));
            let result: Value = serde_json::from_slice(&still_exhausted.stdout).unwrap();
            assert_eq!(result["items"][0]["state"], "exhausted");
        }
    }
}

#[test]
fn exhausted_review_budget_refuses_more_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents/skills/review")).unwrap();
    fs::write(repo.join(".agents/skills/review/SKILL.md"), "Review the change.\n").unwrap();
    fs::write(repo.join(".agents/closeout.yaml"), r#"specVersion: "0.1"
retry:
  maxFailedAttemptsPerItem: 1
  scope: task
items:
  - id: review
    kind: review
    gate: beforePR
    skill: .agents/skills/review/SKILL.md
    independence:
      differentSession: false
      differentModel: false
    failOn: P1
"#).unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    let findings = temp.path().join("findings.json");
    fs::write(&findings, r#"[{"severity":"P1","location":"file","explanation":"fails","evidence":"failure"}]"#).unwrap();
    let args = ["evidence", "add", "--gate", "beforePR", "--item", "review", "--base", "HEAD", "--head", "HEAD", "--task", "task-one", "--session", "reviewer", "--model", "model", "--findings", findings.to_str().unwrap()];
    assert_eq!(closeout(&repo, &args).status.code(), Some(0));
    fs::write(&findings, "[]").unwrap();
    let refused = closeout(&repo, &args);
    assert_eq!(refused.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ask for help"));
    assert_eq!(read_evidence(&repo.join(".closeout")).unwrap().len(), 1);
}

#[test]
fn concurrent_runs_cannot_spend_the_same_retry_budget() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let counter = temp.path().join("attempts");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(repo.join(".agents/closeout.yaml"), serde_json::json!({
        "specVersion": "0.1", "retry": { "maxFailedAttemptsPerItem": 1, "scope": "task" },
        "items": [{"id": "check", "kind": "command", "gate": "beforePR", "timeoutSeconds": 30,
            "exec": ["sh", "-c", "printf x >> \"$1\"; sleep 1; exit 1", "closeout", counter]}]
    }).to_string()).unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    let args = ["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--task", "task-one", "--json"];
    let first = Command::new(env!("CARGO_BIN_EXE_closeout")).args(args).arg("--root").arg(&repo)
        .stdout(std::process::Stdio::null()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !counter.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(counter.exists());
    let concurrent = closeout(&repo, &args);
    assert_eq!(concurrent.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&concurrent.stderr).contains("retry budget"));
    let mut first = first;
    assert_eq!(first.wait().unwrap().code(), Some(3));
    assert_eq!(fs::read_to_string(counter).unwrap(), "x");
    assert_eq!(read_evidence(&repo.join(".closeout")).unwrap().len(), 1);
}

#[test]
fn commands_run_in_a_detached_worktree() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        r#"specVersion: "0.1"
items:
  - id: ok
    kind: command
    gate: beforePR
    exec: ["/usr/bin/pwd"]
    timeoutSeconds: 30
  - id: dirty
    kind: command
    gate: beforePR
    exec: ["/usr/bin/touch", "sentinel"]
    timeoutSeconds: 30
"#,
    )
    .unwrap();
    commit_repo(&repo);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let policy = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy,
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    let decision = run_commands(&RunInput {
        root: repo.clone(),
        policy,
        gate: Gate::BeforePr,
        base_rev: head.clone(),
        head_rev: head.clone(),
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout"),
    })
    .unwrap();
    assert_eq!(decision.decision, DecisionName::Rejected);
    assert_eq!(decision.items[0].message, "exited 0");
    assert_eq!(decision.items[1].message, "command left the worktree dirty");
    assert!(!repo.join("sentinel").exists());
    assert_eq!(resolve_commit(&repo, "HEAD").as_deref(), Some(head.as_str()));
    let logs = all_logs(&repo.join(".closeout"));
    assert!(logs.iter().any(|log| log.contains("closeout-")), "{logs:?}");
    let repo_text = repo.to_string_lossy().into_owned();
    assert!(logs.iter().all(|log| !log.contains(&repo_text)), "{logs:?}");
    let listed = Command::new("git").args(["worktree", "list"]).current_dir(&repo).output().unwrap();
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("closeout-"));
}

#[test]
fn failed_timeout_and_moved_head_reject() {
    let failed = run_exec(&["/usr/bin/false"], 30);
    assert_eq!(failed.decision, DecisionName::Rejected);
    assert_eq!(failed.items[0].message, "command exited 1");

    let timed = run_exec(&["/usr/bin/sleep", "5"], 1);
    assert_eq!(timed.items[0].message, "command timed out");

    let moved = run_exec(&["git", "commit", "--allow-empty", "-m", "move"], 30);
    assert_eq!(moved.items[0].message, "command moved HEAD");
}

#[test]
fn invalid_policy_does_not_execute() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nspecVersion: \"0.1\"\nitems:\n  - id: bad\n    kind: command\n    gate: beforePR\n    exec: [\"/usr/bin/touch\", \"sentinel\"]\n    timeoutSeconds: 30\n",
    )
    .unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    let output = closeout(&repo, &["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD"]);
    assert_eq!(output.status.code(), Some(3));
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(text.contains("duplicated mapping key"), "{text}");
    assert!(!repo.join(".closeout/evidence").exists());
    assert!(!repo.join("sentinel").exists());
}

#[test]
fn cli_exit_codes_and_home_policy() {
    let usage = Command::new(env!("CARGO_BIN_EXE_closeout")).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let repo = temp.path().join("repo");
    fs::create_dir_all(home.join(".agents")).unwrap();
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("README"), "none\n").unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nitems:\n  - id: local-only\n    kind: command\n    gate: beforePR\n    exec: [\"/usr/bin/false\"]\n    timeoutSeconds: 30\n",
    )
    .unwrap();
    let absent = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["validate", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(0), "{}", String::from_utf8_lossy(&absent.stderr));
    assert_eq!(String::from_utf8_lossy(&absent.stdout), "no closeout policy\n");
    let accepted = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["decision", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(accepted.status.code(), Some(0), "{}", String::from_utf8_lossy(&accepted.stderr));
    assert!(String::from_utf8_lossy(&accepted.stdout).contains("no closeout policy"));
    assert!(!String::from_utf8_lossy(&accepted.stdout).contains("local-only"));

    let offline = temp.path().join("offline");
    fs::create_dir_all(&offline).unwrap();
    fs::write(offline.join("README"), "none\n").unwrap();
    commit_repo(&offline);
    let blocked = closeout(&offline, &["validate"]);
    assert_eq!(blocked.status.code(), Some(3));
    let text = format!("{}{}", String::from_utf8_lossy(&blocked.stdout), String::from_utf8_lossy(&blocked.stderr));
    assert!(text.contains("origin/main is unavailable"), "{text}");
}

#[test]
fn origin_main_policy_ignores_local_main() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents/skills/look")).unwrap();
    fs::write(repo.join(".agents/skills/look/SKILL.md"), "remote skill\n").unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        r#"specVersion: "0.1"
items:
  - id: remote-check
    kind: command
    gate: beforePR
    exec: ["/usr/bin/true"]
    timeoutSeconds: 30
  - id: look
    kind: review
    gate: beforePR
    skill: .agents/skills/look/SKILL.md
    independence:
      differentSession: false
      differentModel: false
    failOn: P1
"#,
    )
    .unwrap();
    commit_repo(&repo);
    let remote_digest = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy.digest.unwrap(),
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    publish_origin(&repo);
    fs::write(
        repo.join(".agents/closeout.yaml"),
        r#"specVersion: "0.1"
items:
  - id: local-check
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
"#,
    )
    .unwrap();
    fs::write(repo.join(".agents/skills/look/SKILL.md"), "local skill\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "weaken"]);
    git(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    assert_eq!(resolve_commit(&repo, "HEAD"), resolve_commit(&repo, "origin/main"));

    let listed = closeout(&repo, &["validate", "--json"]);
    assert_eq!(listed.status.code(), Some(0), "{}", String::from_utf8_lossy(&listed.stderr));
    let report: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(report["digest"], remote_digest);
    assert_eq!(report["items"], serde_json::json!(["remote-check", "look"]));

    let ran = closeout(&repo, &["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD"]);
    assert_eq!(ran.status.code(), Some(3), "{}", String::from_utf8_lossy(&ran.stderr));
    let text = String::from_utf8_lossy(&ran.stdout);
    assert!(text.contains("remote-check  passed"), "{text}");
    assert!(text.contains("look"), "{text}");
    assert!(!text.contains("local-check"), "{text}");
}

#[test]
fn try_reads_the_home_policy_and_writes_no_decision() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let repo = temp.path().join("repo");
    fs::create_dir_all(home.join(".agents")).unwrap();
    fs::write(
        home.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nitems:\n  - id: draft-check\n    kind: command\n    gate: beforePR\n    exec: [\"/usr/bin/true\"]\n    timeoutSeconds: 30\n",
    )
    .unwrap();
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("README"), "x\n").unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    let output = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["try", "--root"])
        .arg(&repo)
        .args(["--gate", "beforePR", "--base", "HEAD", "--head", "HEAD"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stderr).contains("local trial from ~/.agents/closeout.yaml is not acceptance"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("accepted beforePR\n"), "{stdout}");
    assert!(stdout.contains("draft-check"), "{stdout}");
    assert!(!repo.join(".closeout").exists());

    let decision = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["decision", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(decision.status.code(), Some(3), "{}", String::from_utf8_lossy(&decision.stderr));
    let decided = format!("{}{}", String::from_utf8_lossy(&decision.stdout), String::from_utf8_lossy(&decision.stderr));
    assert!(decided.contains("draft-check"), "{decided}");
    assert!(decided.contains("Using ~/.agents/closeout.yaml because origin/main has no closeout policy."), "{decided}");

    let sealed = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["try", "--format", "markdown", "--pgp-key", "unused", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(sealed.status.code(), Some(2), "{}", String::from_utf8_lossy(&sealed.stderr));

    let empty_home = temp.path().join("empty-home");
    fs::create_dir_all(&empty_home).unwrap();
    let missing = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["try", "--root"])
        .arg(&repo)
        .args(["--gate", "beforePR", "--base", "HEAD", "--head", "HEAD"])
        .env("HOME", &empty_home)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3));
    let missing_text = format!("{}{}", String::from_utf8_lossy(&missing.stdout), String::from_utf8_lossy(&missing.stderr));
    assert!(missing_text.contains("no closeout policy in ~/.agents/closeout.yaml"), "{missing_text}");
}

#[test]
fn global_policy_fills_the_gap_until_origin_has_one() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let repo = temp.path().join("repo");
    fs::create_dir_all(home.join(".agents")).unwrap();
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("README"), "x\n").unwrap();
    commit_repo(&repo);
    publish_origin(&repo);

    fs::write(home.join(".agents/closeout.yaml"), "specVersion: \"0.9\"\n").unwrap();
    let invalid = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["validate", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(3), "{}", String::from_utf8_lossy(&invalid.stderr));
    let invalid_text = format!("{}{}", String::from_utf8_lossy(&invalid.stdout), String::from_utf8_lossy(&invalid.stderr));
    assert!(!invalid_text.contains("no closeout policy"), "{invalid_text}");

    fs::write(
        home.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nitems:\n  - id: global-check\n    kind: command\n    gate: beforePR\n    exec: [\"/usr/bin/false\"]\n    timeoutSeconds: 30\n",
    )
    .unwrap();
    let ran = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(ran.status.code(), Some(1), "{}", String::from_utf8_lossy(&ran.stderr));
    let ran_text = format!("{}{}", String::from_utf8_lossy(&ran.stdout), String::from_utf8_lossy(&ran.stderr));
    assert!(ran_text.contains("global-check"), "{ran_text}");
    assert!(ran_text.contains("Using ~/.agents/closeout.yaml because origin/main has no closeout policy."), "{ran_text}");

    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(repo.join(".agents/closeout.yaml"), "specVersion: \"0.1\"\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "empty policy"]);
    git(&repo, &["push", "origin", "main"]);
    let preferred = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["run", "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD", "--root"])
        .arg(&repo)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(preferred.status.code(), Some(0), "{}", String::from_utf8_lossy(&preferred.stderr));
    let preferred_text = format!("{}{}", String::from_utf8_lossy(&preferred.stdout), String::from_utf8_lossy(&preferred.stderr));
    assert!(!preferred_text.contains("global-check"), "{preferred_text}");
    assert!(preferred_text.contains("accepted"), "{preferred_text}");

    let offline = temp.path().join("offline");
    fs::create_dir_all(&offline).unwrap();
    fs::write(offline.join("README"), "x\n").unwrap();
    commit_repo(&offline);
    let blocked = Command::new(env!("CARGO_BIN_EXE_closeout"))
        .args(["validate", "--root"])
        .arg(&offline)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(blocked.status.code(), Some(3));
    let blocked_text = format!("{}{}", String::from_utf8_lossy(&blocked.stdout), String::from_utf8_lossy(&blocked.stderr));
    assert!(blocked_text.contains("origin/main is unavailable"), "{blocked_text}");
    assert!(!blocked_text.contains("global-check"), "{blocked_text}");
}

#[test]
fn path_scoped_commands_run_only_when_a_path_matches() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::create_dir_all(repo.join("apps/frontend")).unwrap();
    fs::write(repo.join("apps/frontend/main.ts"), "front\n").unwrap();
    fs::write(repo.join("README"), "x\n").unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        r#"specVersion: "0.1"
items:
  - id: engine
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
    paths: ["apps/engine/**"]
  - id: prefix
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
    paths: ["apps/engine/"]
  - id: sibling
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
    paths: ["apps/engine-extra/**"]
  - id: always
    kind: command
    gate: beforePR
    exec: ["/usr/bin/true"]
    timeoutSeconds: 30
"#,
    )
    .unwrap();
    commit_repo(&repo);
    let base = resolve_commit(&repo, "HEAD").unwrap();
    fs::write(repo.join("apps/frontend/main.ts"), "front2\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "frontend"]);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let policy = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy,
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    let untouched = run_commands(&RunInput {
        root: repo.clone(),
        policy: policy.clone(),
        gate: Gate::BeforePr,
        base_rev: base.clone(),
        head_rev: head,
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout"),
    })
    .unwrap();
    assert_eq!(untouched.decision, DecisionName::Accepted);
    assert_eq!(untouched.items[0].message, "no changed path matches");
    assert_eq!(untouched.items[1].state.as_str(), "skipped");
    assert_eq!(untouched.items[2].state.as_str(), "skipped");
    assert_eq!(untouched.items[3].message, "exited 0");
    assert!(evidence_names(&repo.join(".closeout")).iter().all(|name| !name.contains("engine") && !name.contains("prefix") && !name.contains("sibling")));

    fs::create_dir_all(repo.join("apps/engine")).unwrap();
    fs::write(repo.join("apps/engine/main.ts"), "engine\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "engine"]);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let touched = run_commands(&RunInput {
        root: repo.clone(),
        policy,
        gate: Gate::BeforePr,
        base_rev: base,
        head_rev: head,
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout-engine"),
    })
    .unwrap();
    assert_eq!(touched.decision, DecisionName::Rejected);
    assert_eq!(touched.items[0].message, "command exited 1");
    assert_eq!(touched.items[1].message, "command exited 1");
    assert_eq!(touched.items[2].message, "no changed path matches");
    assert_eq!(touched.items[3].message, "exited 0");
    let names = evidence_names(&repo.join(".closeout-engine"));
    assert!(names.iter().any(|name| name.contains("engine")));
    assert!(names.iter().any(|name| name.contains("prefix")));
    assert!(names.iter().all(|name| !name.contains("sibling")));
}

#[test]
fn a_rename_counts_both_paths() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::create_dir_all(repo.join("apps/engine")).unwrap();
    fs::write(repo.join("apps/engine/main.ts"), "engine\n").unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        r#"specVersion: "0.1"
items:
  - id: old-name
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
    paths: ["apps/engine/main.ts"]
  - id: elsewhere
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
    paths: ["apps/engine-extra/**"]
"#,
    )
    .unwrap();
    commit_repo(&repo);
    let base = resolve_commit(&repo, "HEAD").unwrap();
    git(&repo, &["mv", "apps/engine/main.ts", "apps/engine/lib.ts"]);
    git(&repo, &["commit", "-m", "rename"]);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let policy = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy,
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    let decision = run_commands(&RunInput {
        root: repo.clone(),
        policy,
        gate: Gate::BeforePr,
        base_rev: base,
        head_rev: head,
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout"),
    })
    .unwrap();
    assert_eq!(decision.items[0].message, "command exited 1");
    assert_eq!(decision.items[1].message, "no changed path matches");
    assert_eq!(decision.decision, DecisionName::Rejected);
}

#[test]
fn setup_prepares_the_worktree_for_the_commands() {
    let (_temp, repo, decision) = run_yaml(
        r#"specVersion: "0.1"
setup:
  - id: prepare
    exec: ["/usr/bin/touch", "prepared"]
    timeoutSeconds: 30
items:
  - id: see-it
    kind: command
    gate: beforePR
    exec: ["/usr/bin/test", "-f", "prepared"]
    timeoutSeconds: 30
"#,
    );
    assert_eq!(decision.decision, DecisionName::Accepted);
    assert_eq!(decision.items[0].kind, "setup");
    assert_eq!(decision.items[0].message, "exited 0");
    assert_eq!(decision.items[1].message, "exited 0");
    assert!(!repo.join("prepared").exists());
}

#[test]
fn a_failed_setup_step_does_not_run_later_commands() {
    let (_temp, repo, decision) = run_yaml(
        r#"specVersion: "0.1"
setup:
  - id: install
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
items:
  - id: later-check
    kind: command
    gate: beforePR
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
"#,
    );
    assert_eq!(decision.decision, DecisionName::Rejected);
    assert_eq!(decision.items[0].message, "command exited 1");
    assert_eq!(decision.items[1].state.as_str(), "skipped");
    assert_eq!(decision.items[1].message, "setup failed");
    let names = evidence_names(&repo.join(".closeout"));
    assert!(names.iter().any(|name| name.contains("install")));
    assert!(names.iter().all(|name| !name.contains("later-check")));
}

#[test]
fn path_scoped_setup_stays_idle_when_the_path_is_untouched() {
    let (_temp, repo, decision) = run_yaml(
        r#"specVersion: "0.1"
setup:
  - id: worker
    paths: ["apps/worker/**"]
    exec: ["/usr/bin/false"]
    timeoutSeconds: 30
items:
  - id: always
    kind: command
    gate: beforePR
    exec: ["/usr/bin/true"]
    timeoutSeconds: 30
"#,
    );
    assert_eq!(decision.decision, DecisionName::Accepted);
    assert_eq!(decision.items[0].message, "no changed path matches");
    assert_eq!(decision.items[1].message, "exited 0");
    assert!(evidence_names(&repo.join(".closeout")).iter().all(|name| !name.contains("worker")));
}

#[test]
fn changed_scope_reads_a_diff_only_when_an_item_has_paths() {
    let temp = tempfile::tempdir().unwrap();
    let bare = temp.path().join("empty");
    fs::create_dir_all(&bare).unwrap();
    let unscoped = closeout::ResolvedPolicy {
        absent: false,
        retry: None,
        path: Some(".agents/closeout.yaml".to_string()),
        digest: None,
        files: Vec::new(),
        setup: Vec::new(),
        items: vec![closeout::Item::command("always", vec!["true".to_string()], 30)],
        warnings: Vec::new(),
    };
    assert!(changed_scope(&bare, &unscoped, Gate::BeforePr, "a", "b").unwrap().is_none());
    let scoped = closeout::ResolvedPolicy {
        items: vec![closeout::Item::command("engine", vec!["true".to_string()], 30).with_paths(vec!["src/**".to_string()])],
        ..unscoped
    };
    let err = changed_scope(&bare, &scoped, Gate::BeforePr, "a", "b").unwrap_err();
    assert!(err.starts_with("changed paths are unavailable"), "{err}");
}

fn run_yaml(yaml: &str) -> (tempfile::TempDir, PathBuf, Decision) {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(repo.join(".agents/closeout.yaml"), yaml).unwrap();
    fs::write(repo.join("README"), "x\n").unwrap();
    commit_repo(&repo);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let policy = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy,
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    let decision = run_commands(&RunInput {
        root: repo.clone(),
        policy,
        gate: Gate::BeforePr,
        base_rev: head.clone(),
        head_rev: head,
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout"),
    })
    .unwrap();
    (temp, repo, decision)
}

fn evidence_names(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if !dir.exists() {
        return found;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            }
            found.push(entry.path().to_string_lossy().into_owned());
        }
    }
    found
}

fn run_exec(exec: &[&str], timeout: u64) -> closeout::Decision {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    let argv = exec.iter().map(|arg| format!("\"{arg}\"")).collect::<Vec<_>>().join(", ");
    fs::write(
        repo.join(".agents/closeout.yaml"),
        format!(
            "specVersion: \"0.1\"\nitems:\n  - id: check\n    kind: command\n    gate: beforePR\n    exec: [{argv}]\n    timeoutSeconds: {timeout}\n"
        ),
    )
    .unwrap();
    commit_repo(&repo);
    let head = resolve_commit(&repo, "HEAD").unwrap();
    let before = head.clone();
    let policy = match load_policy(&repo) {
        LoadResult::Ready(policy) => policy,
        LoadResult::Failed { message, .. } => panic!("{message}"),
    };
    let decision = run_commands(&RunInput {
        root: repo.clone(),
        policy,
        gate: Gate::BeforePr,
        base_rev: head.clone(),
        head_rev: head,
        candidate: Candidate::default(),
        evidence_dir: repo.join(".closeout"),
    })
    .unwrap();
    assert_eq!(resolve_commit(&repo, "HEAD").as_deref(), Some(before.as_str()));
    let listed = Command::new("git").args(["worktree", "list"]).current_dir(&repo).output().unwrap();
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("closeout-"));
    decision
}

#[test]
fn sealed_markdown_reports() {
    let keys = tempfile::tempdir().unwrap();
    let keygen = Command::new(env!("CARGO_BIN_EXE_closeout")).args(["keygen", "--pgp", "--out"]).arg(keys.path()).output().unwrap();
    assert_eq!(keygen.status.code(), Some(0), "{}", String::from_utf8_lossy(&keygen.stderr));
    let public = keys.path().join("closeout-public.asc");
    let private = keys.path().join("closeout-private.asc");
    let mode = fs::metadata(&private).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);

    let other = tempfile::tempdir().unwrap();
    let other_keygen = Command::new(env!("CARGO_BIN_EXE_closeout")).args(["keygen", "--pgp", "--out"]).arg(other.path()).output().unwrap();
    assert_eq!(other_keygen.status.code(), Some(0));
    let other_private = other.path().join("closeout-private.asc");

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(
        repo.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nitems:\n  - id: check\n    kind: command\n    gate: beforePR\n    exec: [\"/usr/bin/true\"]\n    timeoutSeconds: 30\n",
    )
    .unwrap();
    commit_repo(&repo);
    publish_origin(&repo);
    let head = resolve_commit(&repo, "HEAD").unwrap();

    let missing = bin(&[
        "run",
        "--root",
        repo.to_str().unwrap(),
        "--gate",
        "beforePR",
        "--base",
        "HEAD",
        "--head",
        "HEAD",
        "--format",
        "markdown",
    ]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());

    let combined = bin(&[
        "run",
        "--root",
        repo.to_str().unwrap(),
        "--gate",
        "beforePR",
        "--base",
        "HEAD",
        "--head",
        "HEAD",
        "--format",
        "markdown",
        "--json",
        "--pgp-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(combined.status.code(), Some(2));

    let sealed = bin(&[
        "run",
        "--root",
        repo.to_str().unwrap(),
        "--gate",
        "beforePR",
        "--base",
        "HEAD",
        "--head",
        "HEAD",
        "--format",
        "markdown",
        "--pgp-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(sealed.status.code(), Some(0), "{}", String::from_utf8_lossy(&sealed.stderr));
    let armor = String::from_utf8(sealed.stdout.clone()).unwrap();
    assert!(armor.contains("BEGIN PGP MESSAGE"));
    let report = temp.path().join("report.asc");
    fs::write(&report, &armor).unwrap();

    let text = bin(&["decision", "--root", repo.to_str().unwrap(), "--gate", "beforePR", "--base", "HEAD", "--head", "HEAD"]);
    assert_eq!(text.status.code(), Some(0), "{}", String::from_utf8_lossy(&text.stderr));
    let verified = bin(&["verify", "--pgp-key", private.to_str().unwrap(), "--head", &head, report.to_str().unwrap()]);
    assert_eq!(verified.status.code(), Some(0), "{}", String::from_utf8_lossy(&verified.stderr));
    assert_eq!(verified.stdout, text.stdout);

    let wrong_head = bin(&[
        "verify",
        "--pgp-key",
        private.to_str().unwrap(),
        "--head",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        report.to_str().unwrap(),
    ]);
    assert_eq!(wrong_head.status.code(), Some(3));

    let mut flipped = armor.into_bytes();
    let start = String::from_utf8_lossy(&flipped).find("BEGIN PGP MESSAGE").unwrap();
    let pos = flipped[start..].iter().position(|byte| *byte == b'A' || *byte == b'B').unwrap() + start;
    flipped[pos] = if flipped[pos] == b'A' { b'B' } else { b'A' };
    let tampered = temp.path().join("tampered.asc");
    fs::write(&tampered, flipped).unwrap();
    let broken = bin(&["verify", "--pgp-key", private.to_str().unwrap(), "--head", &head, tampered.to_str().unwrap()]);
    assert_eq!(broken.status.code(), Some(3));

    let wrong_key = bin(&["verify", "--pgp-key", other_private.to_str().unwrap(), "--head", &head, report.to_str().unwrap()]);
    assert_eq!(wrong_key.status.code(), Some(3));

    let blocked_dir = tempfile::tempdir().unwrap();
    let blocked_repo = blocked_dir.path().join("repo");
    fs::create_dir_all(blocked_repo.join(".agents/skills/look")).unwrap();
    fs::write(blocked_repo.join(".agents/skills/look/SKILL.md"), "Look.\n").unwrap();
    fs::write(
        blocked_repo.join(".agents/closeout.yaml"),
        "specVersion: \"0.1\"\nitems:\n  - id: look\n    kind: review\n    gate: beforePR\n    skill: .agents/skills/look/SKILL.md\n    independence:\n      differentSession: true\n      differentModel: true\n    failOn: P1\n",
    )
    .unwrap();
    commit_repo(&blocked_repo);
    publish_origin(&blocked_repo);
    let blocked_head = resolve_commit(&blocked_repo, "HEAD").unwrap();
    let blocked = bin(&[
        "run",
        "--root",
        blocked_repo.to_str().unwrap(),
        "--gate",
        "beforePR",
        "--base",
        "HEAD",
        "--head",
        "HEAD",
        "--format",
        "markdown",
        "--pgp-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(blocked.status.code(), Some(3), "{}", String::from_utf8_lossy(&blocked.stderr));
    let blocked_report = blocked_dir.path().join("report.asc");
    fs::write(&blocked_report, &blocked.stdout).unwrap();
    let opened = bin(&[
        "verify",
        "--pgp-key",
        private.to_str().unwrap(),
        "--head",
        &blocked_head,
        blocked_report.to_str().unwrap(),
    ]);
    assert_eq!(opened.status.code(), Some(0), "{}", String::from_utf8_lossy(&opened.stderr));
    assert!(String::from_utf8_lossy(&opened.stdout).starts_with("blocked beforePR\n"));
    let required = bin(&[
        "verify",
        "--pgp-key",
        private.to_str().unwrap(),
        "--head",
        &blocked_head,
        "--require-accepted",
        blocked_report.to_str().unwrap(),
    ]);
    assert_eq!(required.status.code(), Some(3));

    let forged = Decision {
        spec_version: SPEC_VERSION.to_string(),
        decision: DecisionName::Accepted,
        gate: Gate::BeforePr,
        base: head.clone(),
        head: head.clone(),
        message: None,
        candidate: Candidate::default(),
        policy: PolicyInfo {
            path: Some(".agents/closeout.yaml".to_string()),
            digest: Some(format!("sha256:{}", "ab".repeat(32))),
            absent: false,
        },
        items: Vec::new(),
        warnings: Vec::new(),
    };
    let forged_armor = seal_report(&fs::read_to_string(&public).unwrap(), &format_markdown(&forged).unwrap()).unwrap();
    let forged_report = temp.path().join("forged.asc");
    fs::write(&forged_report, forged_armor).unwrap();
    let accepted = bin(&[
        "verify",
        "--pgp-key",
        private.to_str().unwrap(),
        "--head",
        &head,
        "--require-accepted",
        forged_report.to_str().unwrap(),
    ]);
    assert_eq!(accepted.status.code(), Some(0), "{}", String::from_utf8_lossy(&accepted.stderr));
    assert!(String::from_utf8_lossy(&accepted.stdout).starts_with("accepted beforePR\n"));
}

fn bin(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_closeout")).args(args).output().unwrap()
}

fn closeout(root: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_closeout"));
    command.args(args).arg("--root").arg(root);
    command.output().unwrap()
}

fn all_logs(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("log") {
                found.push(fs::read_to_string(path).unwrap_or_default());
            }
        }
    }
    found
}

fn publish_origin(repo: &Path) {
    let bare = repo.with_extension("origin.git");
    if bare.exists() {
        fs::remove_dir_all(&bare).unwrap();
    }
    git(repo, &["init", "--bare", "-b", "main", bare.to_str().unwrap()]);
    git(repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(repo, &["config", "protocol.file.allow", "always"]);
    git(repo, &["push", "origin", "main"]);
}

fn commit_repo(dir: &Path) {
    let hooks = dir.join("empty-hooks");
    fs::create_dir_all(&hooks).unwrap();
    git(dir, &["init", "-b", "main"]);
    git(dir, &["config", "user.email", "closeout@example.com"]);
    git(dir, &["config", "user.name", "Closeout"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
    git(dir, &["config", "core.hooksPath", hooks.to_str().unwrap()]);
    git(dir, &["add", "."]);
    git(dir, &["commit", "-m", "init"]);
}

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git").args(args).current_dir(dir).output().unwrap();
    assert!(output.status.success(), "{args:?}\n{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}
