use closeout::{load_policy, ItemBody, LoadResult};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git").arg("-C").arg(repo).args(args).output().unwrap();
    assert!(output.status.success(), "{args:?} {}", String::from_utf8_lossy(&output.stderr));
}

fn commit_repo(repo: &Path) {
    fs::create_dir_all(repo.join("empty-hooks")).unwrap();
    git(repo, &["init", "-b", "main"]);
    git(repo, &["config", "user.email", "closeout@example.com"]);
    git(repo, &["config", "user.name", "Closeout"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(repo, &["config", "core.hooksPath", "empty-hooks"]);
    fs::write(repo.join("README"), "sample\n").unwrap();
    git(repo, &["add", "README"]);
    git(repo, &["commit", "-m", "init"]);
}

fn write_stub(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("closeout-stub");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn consult(repo: &Path, input: &str, bin: Option<&Path>, extra: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new("node");
    command
        .arg(manifest().join("hooks/consult.mjs"))
        .current_dir(repo)
        .env("CLOSEOUT_HOOK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(bin) = bin {
        command.env("CLOSEOUT_BIN", bin);
    } else {
        command.env("CLOSEOUT_BIN", "/no/such/closeout");
    }
    for (key, value) in extra {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn policy_repo(temp: &Path) -> PathBuf {
    let repo = temp.join("repo");
    fs::create_dir_all(repo.join(".agents")).unwrap();
    fs::write(repo.join(".agents/closeout.yaml"), "specVersion: \"0.1\"\n").unwrap();
    commit_repo(&repo);
    repo
}

#[test]
fn bun_example_resolves_quality_commands() {
    let root = manifest().join("examples/bun-project");
    let LoadResult::Ready(policy) = load_policy(&root) else {
        panic!("bun example policy failed to load");
    };
    let ids: Vec<_> = policy.items.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(ids, ["quality/typecheck", "quality/tests", "adversarial-review"]);
    match &policy.items[0].body {
        ItemBody::Command { exec, timeout_seconds } => {
            assert_eq!(exec, &vec!["bun".to_string(), "run".into(), "typecheck".into()]);
            assert_eq!(*timeout_seconds, 120);
        }
        other => panic!("typecheck resolved as {other:?}"),
    }
    match &policy.items[1].body {
        ItemBody::Command { exec, timeout_seconds } => {
            assert_eq!(exec, &vec!["bun".to_string(), "test".into()]);
            assert_eq!(*timeout_seconds, 120);
        }
        other => panic!("tests resolved as {other:?}"),
    }
}

#[test]
fn plugin_packages_match_the_canonical_files() {
    let root = manifest();
    let skill_files = [
        "adversarial-review/SKILL.md",
        "adversarial-review/references/rubric.md",
        "closeout/SKILL.md",
    ];
    for host in ["plugins/claude", "plugins/codex"] {
        for file in skill_files {
            let got = fs::read(root.join(host).join("skills").join(file)).unwrap();
            let want = fs::read(root.join(".agents/skills").join(file)).unwrap();
            assert_eq!(got, want, "{host} {file}");
        }
        let got = fs::read(root.join(host).join("scripts/consult.mjs")).unwrap();
        let want = fs::read(root.join("hooks/consult.mjs")).unwrap();
        assert_eq!(got, want, "{host} consult.mjs");
    }
    let claude: Value = serde_json::from_str(&fs::read_to_string(root.join(".claude-plugin/marketplace.json")).unwrap()).unwrap();
    assert_eq!(claude["plugins"][0]["source"], "./plugins/claude");
    assert!(root.join("plugins/claude/.claude-plugin/plugin.json").is_file());
    let claude_hooks = fs::read_to_string(root.join("plugins/claude/hooks/hooks.json")).unwrap();
    assert!(claude_hooks.contains("${CLAUDE_PLUGIN_ROOT}/scripts/consult.mjs"));
    assert!(claude_hooks.contains("TaskCompleted"));
    assert!(claude_hooks.contains("Stop"));
    let codex: Value = serde_json::from_str(&fs::read_to_string(root.join(".agents/plugins/marketplace.json")).unwrap()).unwrap();
    assert_eq!(codex["plugins"][0]["source"]["source"], "local");
    assert_eq!(codex["plugins"][0]["source"]["path"], "./plugins/codex");
    let codex_hooks = fs::read_to_string(root.join("plugins/codex/hooks/hooks.json")).unwrap();
    assert!(codex_hooks.contains("$PLUGIN_ROOT/scripts/consult.mjs"));
    assert!(root.join("plugins/opencode/closeout.js").is_file());
}

#[test]
fn hook_stays_quiet_without_a_policy_or_when_silenced() {
    let temp = tempfile::tempdir().unwrap();
    let repo = policy_repo(temp.path());
    let sentinel = temp.path().join("ran");
    let stub = write_stub(temp.path(), "touch \"$SENTINEL\"");
    let input = format!("{{\"cwd\":{},\"hook_event_name\":\"Stop\",\"stop_hook_active\":true}}", serde_json::to_string(repo.to_str().unwrap()).unwrap());
    let output = consult(&repo, &input, Some(&stub), &[("SENTINEL", sentinel.to_str().unwrap())]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(!sentinel.exists());
    assert!(!repo.join(".closeout").exists());

    let output = consult(
        &repo,
        &format!("{{\"cwd\":{},\"hook_event_name\":\"Stop\"}}", serde_json::to_string(repo.to_str().unwrap()).unwrap()),
        Some(&stub),
        &[("SENTINEL", sentinel.to_str().unwrap()), ("CLOSEOUT_HOOK", "0")],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(!sentinel.exists());

    fs::remove_file(repo.join(".agents/closeout.yaml")).unwrap();
    let output = consult(
        &repo,
        &format!("{{\"cwd\":{},\"hook_event_name\":\"Stop\"}}", serde_json::to_string(repo.to_str().unwrap()).unwrap()),
        Some(&stub),
        &[("SENTINEL", sentinel.to_str().unwrap())],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(sentinel.exists());
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["decision"], "block");
}

#[test]
fn hook_blocks_when_the_runner_is_missing_or_the_decision_is_not_accepted() {
    let temp = tempfile::tempdir().unwrap();
    let repo = policy_repo(temp.path());
    let cwd = serde_json::to_string(repo.to_str().unwrap()).unwrap();
    let missing = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"TaskCompleted\"}}"), None, &[]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("closeout runner is not available"));
    assert!(!repo.join(".closeout").exists());

    let stop = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), None, &[]);
    assert_eq!(stop.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&stop.stdout).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(parsed["reason"].as_str().unwrap().contains("closeout runner is not available"));

    let rejected = write_stub(
        temp.path(),
        "printf '%s\\n' '{\"decision\":\"rejected\",\"message\":\"a requirement failed\",\"items\":[{\"id\":\"quality/tests\",\"state\":\"failed\",\"message\":\"command exited 1\"}]}'; exit 1",
    );
    let task = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"TaskCompleted\"}}"), Some(&rejected), &[]);
    assert_eq!(task.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&task.stderr);
    assert!(stderr.contains("quality/tests"));
    assert!(stderr.contains("command exited 1"));
    assert!(task.stdout.is_empty());

    let stop = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), Some(&rejected), &[]);
    assert_eq!(stop.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&stop.stdout).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(parsed["reason"].as_str().unwrap().contains("closeout rejected beforePR"));
    assert!(!repo.join(".closeout").exists());

    let skipped = write_stub(
        temp.path(),
        "printf '%s\\n' '{\"decision\":\"blocked\",\"items\":[{\"id\":\"engine\",\"state\":\"skipped\",\"message\":\"no changed path matches\"},{\"id\":\"quality/tests\",\"state\":\"missing\",\"message\":\"no evidence for this candidate and policy\"}]}'; exit 3",
    );
    let quiet = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), Some(&skipped), &[]);
    assert_eq!(quiet.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&quiet.stdout).unwrap();
    let reason = parsed["reason"].as_str().unwrap();
    assert!(reason.contains("closeout blocked beforePR"), "{reason}");
    assert!(reason.contains("quality/tests"), "{reason}");
    assert!(!reason.contains("engine"), "{reason}");
    assert!(!reason.contains("no changed path matches"), "{reason}");

    let accepted = write_stub(temp.path(), "printf '%s\\n' '{\"decision\":\"accepted\",\"items\":[]}'; exit 0");
    let allow = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), Some(&accepted), &[]);
    assert_eq!(allow.status.code(), Some(0));
    assert!(allow.stdout.is_empty());
    assert!(!repo.join(".closeout").exists());
}

#[test]
fn exhausted_budget_allows_stopping_but_blocks_task_completion() {
    let temp = tempfile::tempdir().unwrap();
    let repo = policy_repo(temp.path());
    let stub = write_stub(temp.path(), "printf '%s\\n' '{\"decision\":\"blocked\",\"items\":[{\"id\":\"check\",\"state\":\"exhausted\",\"message\":\"Stop retrying and ask for help.\"}]}'; exit 3");
    let cwd = serde_json::to_string(repo.to_str().unwrap()).unwrap();
    let stop = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), Some(&stub), &[]);
    assert_eq!(stop.status.code(), Some(0));
    let output: Value = serde_json::from_slice(&stop.stdout).unwrap();
    assert!(output.get("decision").is_none());
    assert!(output["systemMessage"].as_str().unwrap().contains("ask for help"));
    let task = consult(&repo, &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"TaskCompleted\"}}"), Some(&stub), &[]);
    assert_eq!(task.status.code(), Some(2));
    let nudged = Command::new("node").arg(manifest().join("tests/opencode_check.mjs"))
        .env("PLUGIN", manifest().join("plugins/opencode/closeout.js"))
        .env("ROOT", &repo).env("MODE", "exhausted").env("CALLS", "4").env("CLOSEOUT_BIN", &stub).output().unwrap();
    assert_eq!(nudged.status.code(), Some(0), "{}", String::from_utf8_lossy(&nudged.stderr));
}

#[test]
fn opencode_plugin_nudges_a_blocked_head_and_stops_at_three() {
    let temp = tempfile::tempdir().unwrap();
    let empty = temp.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    let system = Command::new("node")
        .arg(manifest().join("tests/opencode_check.mjs"))
        .env("PLUGIN", manifest().join("plugins/opencode/closeout.js"))
        .env("ROOT", &empty)
        .env("MODE", "system")
        .env("CLOSEOUT_BIN", "/no/such/closeout")
        .output()
        .unwrap();
    assert_eq!(system.status.code(), Some(0), "{}", String::from_utf8_lossy(&system.stderr));

    let repo = policy_repo(temp.path());
    let accepted = write_stub(temp.path(), "printf '%s\\n' '{\"decision\":\"accepted\",\"items\":[]}'; exit 0");
    let accepted_run = Command::new("node")
        .arg(manifest().join("tests/opencode_check.mjs"))
        .env("PLUGIN", manifest().join("plugins/opencode/closeout.js"))
        .env("ROOT", &repo)
        .env("MODE", "accepted")
        .env("CLOSEOUT_BIN", &accepted)
        .output()
        .unwrap();
    assert_eq!(accepted_run.status.code(), Some(0), "{}", String::from_utf8_lossy(&accepted_run.stderr));
    assert!(!repo.join(".closeout").exists());

    let rejected = write_stub(
        temp.path(),
        "printf '%s\\n' '{\"decision\":\"blocked\",\"message\":\"no evidence for this candidate and policy\",\"items\":[{\"id\":\"engine\",\"state\":\"skipped\",\"message\":\"no changed path matches\"},{\"id\":\"quality/tests\",\"state\":\"missing\",\"message\":\"no evidence for this candidate and policy\"}]}'; exit 3",
    );
    let nudged = Command::new("node")
        .arg(manifest().join("tests/opencode_check.mjs"))
        .env("PLUGIN", manifest().join("plugins/opencode/closeout.js"))
        .env("ROOT", &repo)
        .env("MODE", "rejected")
        .env("CALLS", "4")
        .env("PROMPT_THROWS", "1")
        .env("CLOSEOUT_BIN", &rejected)
        .output()
        .unwrap();
    assert_eq!(nudged.status.code(), Some(0), "{} {}", String::from_utf8_lossy(&nudged.stdout), String::from_utf8_lossy(&nudged.stderr));
    assert!(!repo.join(".closeout/decisions").exists());
}
