use crate::evaluate::{evaluate, EvaluateInput};
use crate::evidence::{next_attempt, read_evidence, write_log, write_record};
use crate::git::{capture, changed_paths, git, porcelain, resolve_commit};
use crate::paths::any_path_matches;
use crate::types::{
    Artifact, Candidate, CommandRecord, Decision, EvidenceRecord, ExecInfo, Gate, Item, ItemBody, ProducerIdentity,
    ResolvedPolicy, OUTPUT_CAP_BYTES, PRODUCER_NAME, SPEC_VERSION, VERSION,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct RunInput {
    pub root: PathBuf,
    pub policy: ResolvedPolicy,
    pub gate: Gate,
    pub base_rev: String,
    pub head_rev: String,
    pub candidate: Candidate,
    pub evidence_dir: PathBuf,
}

pub fn changed_scope(root: &Path, policy: &ResolvedPolicy, gate: Gate, base: &str, head: &str) -> Result<Option<Vec<String>>, String> {
    let needed = policy
        .setup
        .iter()
        .chain(policy.items.iter())
        .any(|item| item.gate == gate && !item.paths.is_empty());
    if !needed {
        return Ok(None);
    }
    changed_paths(root, base, head).map(Some)
}

pub fn run_commands(input: &RunInput) -> Result<Decision, String> {
    let base_sha = resolve_commit(&input.root, &input.base_rev);
    let head_sha = resolve_commit(&input.root, &input.head_rev);
    if base_sha.is_none() || head_sha.is_none() {
        return Ok(evaluate(EvaluateInput {
            policy: &input.policy,
            gate: input.gate,
            base: base_sha.as_deref().unwrap_or(""),
            head: head_sha.as_deref().unwrap_or(""),
            candidate: &input.candidate,
            records: &[],
            changed_paths: None,
            evidence_error: Some("base or head does not resolve to a commit".to_string()),
        }));
    }
    let base = base_sha.unwrap_or_default();
    let head = head_sha.unwrap_or_default();
    let changed = match changed_scope(&input.root, &input.policy, input.gate, &base, &head) {
        Ok(paths) => paths,
        Err(message) => {
            return Ok(evaluate(EvaluateInput {
                policy: &input.policy,
                gate: input.gate,
                base: &base,
                head: &head,
                candidate: &input.candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some(message),
            }));
        }
    };
    let setups: Vec<&Item> = input
        .policy
        .setup
        .iter()
        .filter(|item| item.gate == input.gate && command_in_scope(item, changed.as_deref()))
        .collect();
    let commands: Vec<&Item> = input
        .policy
        .items
        .iter()
        .filter(|item| item.gate == input.gate && matches!(item.body, ItemBody::Command { .. }) && command_in_scope(item, changed.as_deref()))
        .collect();
    let worktree_guard = if setups.is_empty() && commands.is_empty() {
        None
    } else {
        let path = worktree_path();
        let added = git(
            &input.root,
            &[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                path.to_string_lossy().into_owned(),
                head.clone(),
            ],
            Duration::from_secs(30),
        );
        let guard = Worktree { root: input.root.clone(), path };
        if added.code != Some(0) {
            return Ok(evaluate(EvaluateInput {
                policy: &input.policy,
                gate: input.gate,
                base: &base,
                head: &head,
                candidate: &input.candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some("could not create a worktree at the candidate commit".to_string()),
            }));
        }
        Some(guard)
    };
    let mut records = match read_evidence(&input.evidence_dir) {
        Ok(records) => records,
        Err(message) => {
            return Ok(evaluate(EvaluateInput {
                policy: &input.policy,
                gate: input.gate,
                base: &base,
                head: &head,
                candidate: &input.candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some(message),
            }));
        }
    };
    if let (Some(digest), Some(worktree)) = (input.policy.digest.as_deref(), worktree_guard.as_ref()) {
        let mut setup_failed = false;
        for item in setups {
            let failed = run_step(&mut records, input, &base, &head, digest, &worktree.path, item)?;
            if failed {
                setup_failed = true;
                break;
            }
        }
        if !setup_failed {
            for item in commands {
                let _ = run_step(&mut records, input, &base, &head, digest, &worktree.path, item)?;
            }
        }
    }
    let recorded = match read_evidence(&input.evidence_dir) {
        Ok(records) => records,
        Err(message) => {
            return Ok(evaluate(EvaluateInput {
                policy: &input.policy,
                gate: input.gate,
                base: &base,
                head: &head,
                candidate: &input.candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some(message),
            }));
        }
    };
    Ok(evaluate(EvaluateInput {
        policy: &input.policy,
        gate: input.gate,
        base: &base,
        head: &head,
        candidate: &input.candidate,
        records: &recorded,
        changed_paths: changed.as_deref(),
        evidence_error: None,
    }))
}

fn run_step(
    records: &mut Vec<EvidenceRecord>,
    input: &RunInput,
    base: &str,
    head: &str,
    digest: &str,
    cwd: &Path,
    item: &Item,
) -> Result<bool, String> {
    let (ItemBody::Command { exec, timeout_seconds } | ItemBody::Setup { exec, timeout_seconds }) = &item.body else {
        return Ok(false);
    };
    let attempt = next_attempt(records, &item.id, base, head, digest);
    let executed = execute(cwd, exec, *timeout_seconds, head);
    let (log_path, log_hash) = write_log(&input.evidence_dir, digest, head, &item.id, attempt, &executed.log)?;
    let failed = executed.timed_out || executed.head_moved || executed.exit_code != Some(0);
    let record = EvidenceRecord::Command(CommandRecord {
        spec_version: SPEC_VERSION.to_string(),
        item_id: item.id.clone(),
        base: base.to_string(),
        head: head.to_string(),
        policy_digest: digest.to_string(),
        attempt,
        evaluator: identity(),
        producer: identity(),
        exec: ExecInfo {
            argv: exec.clone(),
            exit_code: executed.exit_code,
            timed_out: executed.timed_out,
            dirty: executed.dirty,
            head_moved: executed.head_moved,
            duration_ms: executed.duration_ms,
            truncated: executed.truncated,
        },
        artifacts: vec![Artifact { path: log_path, sha256: log_hash }],
    });
    write_record(&input.evidence_dir, &record)?;
    records.push(record);
    Ok(failed)
}

fn command_in_scope(item: &Item, changed: Option<&[String]>) -> bool {
    item.paths.is_empty() || changed.is_some_and(|paths| any_path_matches(&item.paths, paths))
}

struct Execution {
    exit_code: Option<i32>,
    timed_out: bool,
    dirty: bool,
    head_moved: bool,
    duration_ms: u64,
    truncated: bool,
    log: String,
}

fn execute(cwd: &Path, exec: &[String], timeout_seconds: u64, head: &str) -> Execution {
    let started = Instant::now();
    let Some((program, args)) = exec.split_first() else {
        return Execution {
            exit_code: None,
            timed_out: false,
            dirty: false,
            head_moved: false,
            duration_ms: 0,
            truncated: false,
            log: "STDOUT\n\nSTDERR\n".to_string(),
        };
    };
    let before = porcelain(cwd);
    let captured = capture(program, args, cwd, Duration::from_secs(timeout_seconds), Some(OUTPUT_CAP_BYTES));
    let after = porcelain(cwd);
    let now = resolve_commit(cwd, "HEAD");
    let dirty = match &after {
        None => true,
        Some(text) if text.is_empty() => false,
        Some(text) => before.as_ref() != Some(text),
    };
    Execution {
        exit_code: if captured.spawn_failed { None } else { captured.code },
        timed_out: captured.timed_out,
        dirty,
        head_moved: now.as_deref() != Some(head),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        truncated: captured.truncated,
        log: format!("STDOUT\n{}\nSTDERR\n{}", captured.stdout, captured.stderr),
    }
}

fn identity() -> ProducerIdentity {
    ProducerIdentity {
        name: PRODUCER_NAME.to_string(),
        version: VERSION.to_string(),
    }
}

fn worktree_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or(0);
    std::env::temp_dir().join(format!("closeout-{}-{n}-{nanos}", std::process::id()))
}

struct Worktree {
    root: PathBuf,
    path: PathBuf,
}

impl Drop for Worktree {
    fn drop(&mut self) {
        let _ = git(
            &self.root,
            &[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                self.path.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(30),
        );
        let _ = fs::remove_dir_all(&self.path);
    }
}
