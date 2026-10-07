use closeout::{load_policy, ItemBody, LoadResult};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
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
fn hook_stays_quiet_outside_a_repository() {
    let temp = tempfile::tempdir().unwrap();
    let sentinel = temp.path().join("ran");
    let stub = write_stub(temp.path(), "touch \"$SENTINEL\"");
    let plain = temp.path().join("plain");
    let unborn = temp.path().join("unborn");
    let staged = temp.path().join("staged");
    let ceiling = temp.path().join("outer/ceiling");
    let ceiled = ceiling.join("plain");
    fs::create_dir_all(&plain).unwrap();
    fs::create_dir_all(&unborn).unwrap();
    fs::create_dir_all(&staged).unwrap();
    fs::create_dir_all(&ceiled).unwrap();
    fs::write(temp.path().join("outer/.git"), "").unwrap();
    git(&unborn, &["init", "-b", "main"]);
    git(&staged, &["init", "-b", "main"]);
    fs::write(staged.join("README"), "staged\n").unwrap();
    git(&staged, &["add", "README"]);
    let ceilings = format!("{}:{}", temp.path().display(), ceiling.display());
    let marked = fs::canonicalize(&plain)
        .unwrap()
        .ancestors()
        .any(|dir| [".git", "HEAD", "objects", "refs"].iter().any(|name| fs::symlink_metadata(dir.join(name)).is_ok()));
    for trace in ["", "1"] {
        let cwd = serde_json::to_string(plain.to_str().unwrap()).unwrap();
        for event in ["Stop", "TaskCompleted"] {
            let output = consult(
                &plain,
                &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"{event}\"}}"),
                Some(&stub),
                &[("SENTINEL", sentinel.to_str().unwrap()), ("GIT_CEILING_DIRECTORIES", temp.path().to_str().unwrap()), ("GIT_TRACE2", trace)],
            );
            let quiet = output.status.code() == Some(0) && output.stdout.is_empty();
            assert_eq!(quiet, !marked, "{trace} {event} {}", String::from_utf8_lossy(&output.stdout));
            assert!(!sentinel.exists());
        }
    }

    let missing = serde_json::to_string(temp.path().join("missing").to_str().unwrap()).unwrap();
    let output = consult(
        temp.path(),
        &format!("{{\"cwd\":{missing},\"hook_event_name\":\"Stop\"}}"),
        Some(&stub),
        &[("SENTINEL", sentinel.to_str().unwrap())],
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(!sentinel.exists());

    let broken = temp.path().join("broken");
    commit_repo(&broken);
    fs::write(broken.join(".git/refs/heads/main"), "zzz\n").unwrap();
    let lost = temp.path().join("lost");
    commit_repo(&lost);
    let head = String::from_utf8(Command::new("git").arg("-C").arg(&lost).args(["rev-parse", "HEAD"]).output().unwrap().stdout).unwrap();
    let head = head.trim();
    fs::remove_file(lost.join(".git/objects").join(&head[..2]).join(&head[2..])).unwrap();
    let phrase = temp.path().join("not a git repository/missing");
    let config = temp.path().join("config");
    commit_repo(&config);
    git(&config, &["config", "core.repositoryformatversion", "not a git repository"]);
    let headless = temp.path().join("headless");
    commit_repo(&headless);
    fs::remove_file(headless.join(".git/HEAD")).unwrap();
    let nested = headless.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let objectless = temp.path().join("objectless");
    commit_repo(&objectless);
    fs::remove_dir_all(objectless.join(".git/objects")).unwrap();
    let dangling = temp.path().join("dangling");
    fs::create_dir_all(&dangling).unwrap();
    fs::write(dangling.join(".git"), format!("gitdir: {}\n", temp.path().join("gone/.git/worktrees/dangling").display())).unwrap();
    let orphaned = temp.path().join("orphaned");
    commit_repo(&orphaned);
    git(&orphaned, &["branch", "retained"]);
    fs::remove_file(orphaned.join(".git/refs/heads/main")).unwrap();
    let erased = temp.path().join("erased");
    commit_repo(&erased);
    fs::remove_file(erased.join(".git/refs/heads/main")).unwrap();
    fs::remove_dir_all(erased.join(".git/logs")).unwrap();
    let linked = temp.path().join("linked");
    commit_repo(&linked);
    fs::rename(linked.join(".git"), linked.join(".saved-git")).unwrap();
    std::os::unix::fs::symlink(temp.path().join("nowhere"), linked.join(".git")).unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&nested, &alias).unwrap();
    let deep = temp.path().join("deep");
    commit_repo(&deep);
    fs::create_dir_all(deep.join("one/two/three")).unwrap();
    fs::remove_file(deep.join(".git/HEAD")).unwrap();
    std::os::unix::fs::symlink(deep.join("one/two/three"), temp.path().join("hop")).unwrap();
    let climb = temp.path().join("hop/../../..");
    let source = temp.path().join("source");
    commit_repo(&source);
    let mut bare = Vec::new();
    for part in ["HEAD", "objects", "refs"] {
        let dir = temp.path().join(format!("bare-without-{part}"));
        git(temp.path(), &["clone", "--quiet", "--bare", source.to_str().unwrap(), dir.to_str().unwrap()]);
        let path = dir.join(part);
        if path.is_dir() {
            fs::remove_dir_all(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        bare.push(dir);
    }
    for dir in [&broken, &lost, &phrase, &config, &headless, &nested, &objectless, &dangling, &orphaned, &erased, &linked, &alias, &unborn, &staged, &ceiled, &bare[0], &bare[1], &bare[2], &climb] {
        let cwd = serde_json::to_string(dir.to_str().unwrap()).unwrap();
        let output = consult(
            temp.path(),
            &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
            Some(&stub),
            &[("SENTINEL", sentinel.to_str().unwrap())],
        );
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["decision"], "block", "{dir:?}");
        assert!(!sentinel.exists());
    }
    let cwd = serde_json::to_string(ceiled.to_str().unwrap()).unwrap();
    let output = consult(
        &ceiled,
        &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
        Some(&stub),
        &[("SENTINEL", sentinel.to_str().unwrap()), ("GIT_CEILING_DIRECTORIES", &ceilings)],
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(!sentinel.exists());

    let node = Command::new("node").args(["-p", "process.execPath"]).current_dir(temp.path()).output().unwrap().stdout;
    let node = PathBuf::from(String::from_utf8(node).unwrap().trim());
    let odd = temp.path().join(std::ffi::OsStr::from_bytes(b"odd\xff"));
    if fs::create_dir(&odd).is_ok() {
        commit_repo(&odd);
        fs::remove_file(odd.join(".git/HEAD")).unwrap();
        let ascii = temp.path().join("ascii");
        std::os::unix::fs::symlink(&odd, &ascii).unwrap();
        let cwd = serde_json::to_string(ascii.to_str().unwrap()).unwrap();
        let output = consult(
            temp.path(),
            &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
            Some(&stub),
            &[("SENTINEL", sentinel.to_str().unwrap())],
        );
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["decision"], "block");
        assert!(!sentinel.exists());

        let decoded = temp.path().join("odd\u{FFFD}");
        fs::create_dir_all(&decoded).unwrap();
        let cwd = serde_json::to_string(decoded.to_str().unwrap()).unwrap();
        let path = format!("{}:{}", node.parent().unwrap().display(), std::env::var("PATH").unwrap());
        let legacy = temp.path().join("legacy.mjs");
        fs::write(&legacy, "delete String.prototype.isWellFormed;\n").unwrap();
        let options = format!("--import={}", legacy.display());
        let surrogate = format!("{{\"cwd\":\"{}/odd\\udcff\",\"hook_event_name\":\"Stop\"}}", temp.path().display());
        for input in ["{\"hook_event_name\":\"Stop\"}".to_string(), format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"), surrogate] {
            let output = consult(&odd, &input, Some(&stub), &[("SENTINEL", sentinel.to_str().unwrap()), ("PATH", &path), ("NODE_OPTIONS", &options)]);
            let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(parsed["decision"], "block", "{input}");
            assert!(!sentinel.exists());
        }
    }

    let resolved = temp.path().join("resolved");
    std::os::unix::fs::symlink(&headless, &resolved).unwrap();
    for ceilings in ["..".to_string(), format!(":{}", resolved.display())] {
        let cwd = serde_json::to_string(nested.to_str().unwrap()).unwrap();
        let output = consult(
            &nested,
            &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
            Some(&stub),
            &[("SENTINEL", sentinel.to_str().unwrap()), ("GIT_CEILING_DIRECTORIES", &ceilings)],
        );
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["decision"], "block", "{ceilings}");
        assert!(!sentinel.exists());
    }

    let repo = policy_repo(temp.path());
    for dir in [&repo, &unborn, &plain] {
        let cwd = serde_json::to_string(dir.to_str().unwrap()).unwrap();
        let output = consult(
            dir,
            &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
            Some(&stub),
            &[("SENTINEL", sentinel.to_str().unwrap()), ("CLOSEOUT_BASE", "no-such-ref"), ("GIT_CEILING_DIRECTORIES", temp.path().to_str().unwrap())],
        );
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["decision"], "block", "{dir:?}");
        assert_eq!(parsed["reason"], "base or head does not resolve to a commit");
        assert!(!sentinel.exists());
    }

    let external = temp.path().join("external");
    git(temp.path(), &["clone", "--quiet", "--bare", source.to_str().unwrap(), external.to_str().unwrap()]);
    git(&external, &["config", "core.repositoryformatversion", "broken\nfatal: not a git repository (or any of the parent directories): .git"]);
    let cwd = serde_json::to_string(plain.to_str().unwrap()).unwrap();
    let injected = "invalid\nfatal: not a git repository (or any of the parent directories): .git";
    let gitless = temp.path().join("gitless");
    fs::create_dir_all(&gitless).unwrap();
    std::os::unix::fs::symlink(&node, gitless.join("node")).unwrap();
    for env in [
        ("GIT_DIR", external.to_str().unwrap()),
        ("GIT_DIR", ""),
        ("CLOSEOUT_BASE", ""),
        ("GIT_DISCOVERY_ACROSS_FILESYSTEM", injected),
        ("PATH", gitless.to_str().unwrap()),
    ] {
        let output = consult(
            &plain,
            &format!("{{\"cwd\":{cwd},\"hook_event_name\":\"Stop\"}}"),
            Some(&stub),
            &[("SENTINEL", sentinel.to_str().unwrap()), env, ("GIT_CEILING_DIRECTORIES", temp.path().to_str().unwrap())],
        );
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["decision"], "block", "{env:?}");
        assert!(!sentinel.exists());
    }
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
