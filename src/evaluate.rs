use crate::paths::any_path_matches;
use crate::types::{
    Candidate, CommandRecord, Decision, DecisionName, EvidenceRecord, ExecInfo, Gate, Item, ItemBody, ItemResult, ItemState,
    PolicyInfo, ResolvedPolicy, RetryScope, ReviewRecord, Severity, SPEC_VERSION, PRODUCER_NAME, VERSION,
};
use std::collections::HashSet;

pub struct EvaluateInput<'a> {
    pub policy: &'a ResolvedPolicy,
    pub gate: Gate,
    pub base: &'a str,
    pub head: &'a str,
    pub candidate: &'a Candidate,
    pub records: &'a [EvidenceRecord],
    pub changed_paths: Option<&'a [String]>,
    pub evidence_error: Option<String>,
}

pub fn evaluate(input: EvaluateInput<'_>) -> Decision {
    let decision = Decision {
        spec_version: SPEC_VERSION.to_string(),
        decision: DecisionName::Accepted,
        gate: input.gate,
        base: input.base.to_string(),
        head: input.head.to_string(),
        message: None,
        candidate: input.candidate.clone(),
        policy: PolicyInfo {
            path: input.policy.path.clone(),
            digest: input.policy.digest.clone(),
            absent: input.policy.absent,
        },
        items: Vec::new(),
        warnings: input.policy.warnings.clone(),
    };
    if let Some(message) = input.evidence_error.clone().or_else(|| retry_task_error(input.policy, input.candidate)) {
        return Decision {
            decision: DecisionName::Blocked,
            message: Some(message),
            ..decision
        };
    }
    if input.policy.absent {
        return Decision {
            decision: DecisionName::Accepted,
            message: Some("no closeout policy".to_string()),
            ..decision
        };
    }
    let mut items = Vec::new();
    let mut setup_failed = false;
    for step in input.policy.setup.iter().filter(|item| item.gate == input.gate) {
        let mut result = judge(step, &input);
        if setup_failed && result.state == ItemState::Missing {
            result.state = ItemState::Skipped;
            result.message = "setup failed".to_string();
        }
        if matches!(result.state, ItemState::Failed | ItemState::Exhausted) {
            setup_failed = true;
        }
        items.push(result);
    }
    for item in input.policy.items.iter().filter(|item| item.gate == input.gate) {
        let mut result = judge(item, &input);
        if setup_failed && matches!(item.body, ItemBody::Command { .. }) && result.state == ItemState::Missing {
            result.state = ItemState::Skipped;
            result.message = "setup failed".to_string();
        }
        items.push(result);
    }
    let name = if items.iter().any(|item| item.state.blocks()) {
        DecisionName::Blocked
    } else if items.iter().any(|item| item.state == ItemState::Failed) {
        DecisionName::Rejected
    } else {
        DecisionName::Accepted
    };
    Decision { decision: name, items, ..decision }
}

pub fn blocked_policy(message: &str, gate: Gate, candidate: Candidate) -> Decision {
    Decision {
        spec_version: SPEC_VERSION.to_string(),
        decision: DecisionName::Blocked,
        gate,
        base: String::new(),
        head: String::new(),
        message: Some(message.to_string()),
        candidate,
        policy: PolicyInfo {
            path: None,
            digest: None,
            absent: false,
        },
        items: Vec::new(),
        warnings: Vec::new(),
    }
}

fn judge(item: &Item, input: &EvaluateInput<'_>) -> ItemResult {
    if !item.paths.is_empty() {
        let Some(changed) = input.changed_paths else {
            return ItemResult {
                id: item.id.clone(),
                kind: item.kind_name().to_string(),
                state: ItemState::Invalid,
                message: "changed paths are unavailable".to_string(),
                attempt: None,
            };
        };
        if !any_path_matches(&item.paths, changed) {
            return ItemResult {
                id: item.id.clone(),
                kind: item.kind_name().to_string(),
                state: ItemState::Skipped,
                message: "no changed path matches".to_string(),
                attempt: None,
            };
        }
    }
    if let ItemBody::Unsupported { .. } = &item.body {
        return ItemResult {
            id: item.id.clone(),
            kind: item.kind_name().to_string(),
            state: ItemState::Unsupported,
            message: format!("kind {} is not supported", item.kind_name()),
            attempt: None,
        };
    }
    if let Some(result) = retry_block(input.policy, item, input.base, input.head, input.candidate, input.records) {
        return result;
    }
    let digest = input.policy.digest.as_deref().unwrap_or("");
    let matching: Vec<&EvidenceRecord> = input
        .records
        .iter()
        .filter(|record| record.item_id() == item.id && record.base() == input.base && record.head() == input.head && record.policy_digest() == digest)
        .filter(|record| input.policy.retry.as_ref().is_none_or(|retry| retry.scope != RetryScope::Task || record.task() == input.candidate.task))
        .collect();
    if matching.is_empty() {
        let any = input.records.iter().any(|record| {
            record.item_id() == item.id && input.policy.retry.as_ref().is_none_or(|retry| retry.scope != RetryScope::Task || record.task() == input.candidate.task)
        });
        return ItemResult {
            id: item.id.clone(),
            kind: item.kind_name().to_string(),
            state: if any { ItemState::Stale } else { ItemState::Missing },
            message: if any {
                "evidence is for a different candidate or policy".to_string()
            } else {
                "no evidence for this candidate and policy".to_string()
            },
            attempt: None,
        };
    }
    let mut attempts = HashSet::new();
    if matching.iter().any(|record| !attempts.insert(record.attempt())) {
        return ItemResult {
            id: item.id.clone(),
            kind: item.kind_name().to_string(),
            state: ItemState::Invalid,
            message: "duplicate evidence attempt".to_string(),
            attempt: None,
        };
    }
    let latest = matching.iter().max_by_key(|record| record.attempt()).expect("matching evidence");
    match &item.body {
        ItemBody::Command { exec, .. } => match latest {
            EvidenceRecord::Command(record) => judge_command(item, exec, record, false),
            EvidenceRecord::Review(record) => kind_mismatch(item, record.attempt),
        },
        ItemBody::Setup { exec, .. } => match latest {
            EvidenceRecord::Command(record) => judge_command(item, exec, record, true),
            EvidenceRecord::Review(record) => kind_mismatch(item, record.attempt),
        },
        ItemBody::Review { independence, fail_on, .. } => match latest {
            EvidenceRecord::Review(record) => judge_review(item, independence, *fail_on, record, input.candidate),
            EvidenceRecord::Command(record) => kind_mismatch(item, record.attempt),
        },
        ItemBody::Unsupported { .. } => unreachable!(),
    }
}

pub fn retry_task_error(policy: &ResolvedPolicy, candidate: &Candidate) -> Option<String> {
    if policy.retry.as_ref().is_some_and(|retry| retry.scope == RetryScope::Task) && candidate.task.trim().is_empty() {
        return Some("task retry scope requires --task with a stable task ID".to_string());
    }
    if !candidate.task.is_empty() && (candidate.task.trim().is_empty() || candidate.task.len() > 256) {
        return Some("task ID must contain 1 to 256 bytes and cannot be blank".to_string());
    }
    None
}

pub fn retry_block(
    policy: &ResolvedPolicy,
    item: &Item,
    base: &str,
    head: &str,
    candidate: &Candidate,
    records: &[EvidenceRecord],
) -> Option<ItemResult> {
    let retry = policy.retry.as_ref()?;
    let digest = policy.digest.as_deref().unwrap_or("");
    let mut seen = HashSet::new();
    let mut failed = 0;
    for record in records.iter().filter(|record| {
        record.item_id() == item.id && record.policy_digest() == digest && match retry.scope {
            RetryScope::Task => !candidate.task.is_empty() && record.task() == candidate.task,
            RetryScope::Candidate => record.base() == base && record.head() == head,
        }
    }) {
        if !seen.insert((record.base(), record.head(), record.attempt())) {
            return Some(ItemResult {
                id: item.id.clone(), kind: item.kind_name().to_string(), state: ItemState::Invalid,
                message: "duplicate evidence attempt".to_string(), attempt: None,
            });
        }
        let counts = match (&item.body, record) {
            (ItemBody::Command { exec, .. }, EvidenceRecord::Command(record)) => judge_command(item, exec, record, false).state == ItemState::Failed,
            (ItemBody::Setup { exec, .. }, EvidenceRecord::Command(record)) => judge_command(item, exec, record, true).state == ItemState::Failed,
            (ItemBody::Review { independence, fail_on, .. }, EvidenceRecord::Review(record)) => judge_review(item, independence, *fail_on, record, candidate).state == ItemState::Failed,
            _ => false,
        };
        failed += u64::from(counts);
    }
    if failed < retry.max_failed_attempts_per_item {
        return None;
    }
    Some(ItemResult {
        id: item.id.clone(),
        kind: item.kind_name().to_string(),
        state: ItemState::Exhausted,
        message: format!("{failed} of {} allowed failed attempts used. Stop retrying and ask for help.", retry.max_failed_attempts_per_item),
        attempt: None,
    })
}

fn kind_mismatch(item: &Item, attempt: u64) -> ItemResult {
    ItemResult {
        id: item.id.clone(),
        kind: item.kind_name().to_string(),
        state: ItemState::Invalid,
        message: "evidence kind does not match the requirement".to_string(),
        attempt: Some(attempt),
    }
}

fn judge_command(item: &Item, exec: &[String], record: &CommandRecord, allow_dirty: bool) -> ItemResult {
    let mut result = ItemResult {
        id: item.id.clone(),
        kind: item.kind_name().to_string(),
        state: ItemState::Passed,
        message: String::new(),
        attempt: Some(record.attempt),
    };
    if record.producer.name != PRODUCER_NAME || record.producer.version != VERSION {
        result.state = ItemState::Untrusted;
        result.message = "command evidence producer is not trusted".to_string();
        return result;
    }
    if record.exec.argv != exec {
        result.state = ItemState::Invalid;
        result.message = "command evidence does not match the policy argv".to_string();
        return result;
    }
    apply_exec(&mut result, &record.exec, allow_dirty);
    result
}

fn apply_exec(result: &mut ItemResult, exec: &ExecInfo, allow_dirty: bool) {
    if exec.timed_out {
        result.state = ItemState::Failed;
        result.message = "command timed out".to_string();
        return;
    }
    let Some(code) = exec.exit_code else {
        result.state = ItemState::Failed;
        result.message = "command could not start".to_string();
        return;
    };
    if code != 0 {
        result.state = ItemState::Failed;
        result.message = format!("command exited {code}");
        return;
    }
    if exec.head_moved {
        result.state = ItemState::Failed;
        result.message = "command moved HEAD".to_string();
        return;
    }
    if exec.dirty && !allow_dirty {
        result.state = ItemState::Failed;
        result.message = "command left the worktree dirty".to_string();
        return;
    }
    result.state = ItemState::Passed;
    result.message = "exited 0".to_string();
}

fn judge_review(
    item: &Item,
    independence: &crate::types::Independence,
    fail_on: Severity,
    record: &ReviewRecord,
    candidate: &Candidate,
) -> ItemResult {
    let mut result = ItemResult {
        id: item.id.clone(),
        kind: item.kind_name().to_string(),
        state: ItemState::Passed,
        message: String::new(),
        attempt: Some(record.attempt),
    };
    if let Some(finding) = record
        .findings
        .iter()
        .filter(|finding| finding.severity.rank() <= fail_on.rank())
        .min_by_key(|finding| finding.severity.rank())
    {
        result.state = ItemState::Failed;
        result.message = format!("finding at {} meets failOn {}", finding.severity.as_str(), fail_on.as_str());
        return result;
    }
    if let Some(message) = independence_failure(independence, record, candidate) {
        result.state = ItemState::Independence;
        result.message = message;
        return result;
    }
    result.state = ItemState::Passed;
    result.message = "review findings satisfy the policy".to_string();
    result
}

fn independence_failure(independence: &crate::types::Independence, record: &ReviewRecord, candidate: &Candidate) -> Option<String> {
    if independence.different_session && !distinct(&candidate.session, &record.producer.session) {
        return Some("reviewer does not satisfy differentSession".to_string());
    }
    if independence.different_model && !distinct(&candidate.model, &record.producer.model) {
        return Some("reviewer does not satisfy differentModel".to_string());
    }
    None
}

fn distinct(left: &str, right: &str) -> bool {
    !left.trim().is_empty() && !right.trim().is_empty() && left != right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecInfo, Finding, Independence, ProducerIdentity, ReviewProducer, PRODUCER_NAME, VERSION};

    fn policy(items: Vec<Item>) -> ResolvedPolicy {
        ResolvedPolicy {
            absent: false,
            retry: None,
            path: Some(".agents/closeout.yaml".to_string()),
            digest: Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            files: Vec::new(),
            setup: Vec::new(),
            items,
            warnings: Vec::new(),
        }
    }

    fn candidate() -> Candidate {
        Candidate {
            task: String::new(),
            session: "implementer".to_string(),
            model: "model-a".to_string(),
            provider: "codex".to_string(),
        }
    }

    fn command_record(argv: &[&str], exit_code: Option<i32>, timed_out: bool, dirty: bool, head_moved: bool) -> EvidenceRecord {
        EvidenceRecord::Command(CommandRecord {
            task: String::new(),
            spec_version: SPEC_VERSION.to_string(),
            item_id: "check".to_string(),
            base: "b".to_string(),
            head: "h".to_string(),
            policy_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            attempt: 1,
            evaluator: ProducerIdentity { name: PRODUCER_NAME.to_string(), version: VERSION.to_string() },
            producer: ProducerIdentity { name: PRODUCER_NAME.to_string(), version: VERSION.to_string() },
            exec: ExecInfo {
                argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
                exit_code,
                timed_out,
                dirty,
                head_moved,
                duration_ms: 1,
                truncated: false,
            },
            artifacts: Vec::new(),
        })
    }

    fn review_record(session: &str, model: &str, findings: Vec<Finding>) -> EvidenceRecord {
        EvidenceRecord::Review(ReviewRecord {
            task: String::new(),
            spec_version: SPEC_VERSION.to_string(),
            item_id: "adversarial-review".to_string(),
            base: "b".to_string(),
            head: "h".to_string(),
            policy_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            attempt: 1,
            evaluator: ProducerIdentity { name: PRODUCER_NAME.to_string(), version: VERSION.to_string() },
            producer: ReviewProducer { session: session.to_string(), model: model.to_string(), provider: "other".to_string() },
            findings,
            artifacts: Vec::new(),
        })
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            severity,
            location: "src/lib.rs".to_string(),
            explanation: "checked the branch".to_string(),
            evidence: "the assertion failed".to_string(),
        }
    }

    fn decide(policy: &ResolvedPolicy, records: &[EvidenceRecord]) -> Decision {
        evaluate(EvaluateInput {
            policy,
            gate: Gate::BeforePr,
            base: "b",
            head: "h",
            candidate: &candidate(),
            records,
            changed_paths: None,
            evidence_error: None,
        })
    }

    fn decide_scoped(policy: &ResolvedPolicy, records: &[EvidenceRecord], changed: Option<&[String]>) -> Decision {
        evaluate(EvaluateInput {
            policy,
            gate: Gate::BeforePr,
            base: "b",
            head: "h",
            candidate: &candidate(),
            records,
            changed_paths: changed,
            evidence_error: None,
        })
    }

    #[test]
    fn retry_counts_only_failed_evidence_in_the_selected_scope() {
        let mut loaded = policy(vec![Item::command("check", vec!["true".to_string()], 30)]);
        loaded.retry = Some(crate::types::RetryPolicy { max_failed_attempts_per_item: 1, scope: RetryScope::Candidate });
        let mut untrusted = command_record(&["true"], Some(1), false, false, false);
        if let EvidenceRecord::Command(record) = &mut untrusted {
            record.producer.name = "unknown".to_string();
        }
        assert_eq!(decide(&loaded, &[untrusted]).items[0].state, ItemState::Untrusted);
        let passed = command_record(&["true"], Some(0), false, false, false);
        assert_eq!(decide(&loaded, &[passed]).decision, DecisionName::Accepted);
        let mut failed = command_record(&["true"], Some(1), false, false, false);
        assert_eq!(decide(&loaded, &[failed.clone(), failed.clone()]).items[0].state, ItemState::Invalid);
        assert_eq!(decide(&loaded, &[failed.clone()]).items[0].state, ItemState::Exhausted);
        if let EvidenceRecord::Command(record) = &mut failed {
            record.head = "earlier".to_string();
        }
        assert_eq!(decide(&loaded, &[failed.clone()]).items[0].state, ItemState::Stale);
        loaded.retry.as_mut().unwrap().scope = RetryScope::Task;
        let mut candidate = candidate();
        candidate.task = "task-one".to_string();
        if let EvidenceRecord::Command(record) = &mut failed {
            record.task = candidate.task.clone();
        }
        assert!(retry_block(&loaded, &loaded.items[0], "new-base", "new-head", &candidate, &[failed.clone()]).is_some());
        candidate.task = "task-two".to_string();
        assert!(retry_block(&loaded, &loaded.items[0], "new-base", "new-head", &candidate, &[failed]).is_none());
    }

    #[test]
    fn command_outcomes_follow_the_table() {
        let item = Item::command("check", vec!["true".to_string()], 30);
        let loaded = policy(vec![item]);
        assert_eq!(decide(&loaded, &[]).items[0].state, ItemState::Missing);
        let mut stale = command_record(&["true"], Some(0), false, false, false);
        if let EvidenceRecord::Command(record) = &mut stale {
            record.head = "other".to_string();
        }
        assert_eq!(decide(&loaded, &[stale]).items[0].state, ItemState::Stale);
        let mut untrusted = command_record(&["true"], Some(0), false, false, false);
        if let EvidenceRecord::Command(record) = &mut untrusted {
            record.producer.name = "someone".to_string();
            record.exec.argv = vec!["false".to_string()];
        }
        let judged = decide(&loaded, &[untrusted]);
        assert_eq!(judged.items[0].state, ItemState::Untrusted);
        let wrong = command_record(&["false"], Some(0), false, false, false);
        assert_eq!(decide(&loaded, &[wrong]).items[0].message, "command evidence does not match the policy argv");
        let timed = command_record(&["true"], None, true, false, false);
        assert_eq!(decide(&loaded, &[timed]).items[0].message, "command timed out");
        let dead = command_record(&["true"], None, false, true, true);
        assert_eq!(decide(&loaded, &[dead]).items[0].message, "command could not start");
        let failed = command_record(&["true"], Some(2), false, false, false);
        assert_eq!(decide(&loaded, &[failed]).items[0].message, "command exited 2");
        let moved = command_record(&["true"], Some(0), false, true, true);
        assert_eq!(decide(&loaded, &[moved]).items[0].message, "command moved HEAD");
        let dirty = command_record(&["true"], Some(0), false, true, false);
        assert_eq!(decide(&loaded, &[dirty]).items[0].message, "command left the worktree dirty");
        let passed = command_record(&["true"], Some(0), false, false, false);
        let decision = decide(&loaded, &[passed]);
        assert_eq!(decision.decision, DecisionName::Accepted);
        assert_eq!(decision.items[0].message, "exited 0");
    }

    #[test]
    fn review_findings_are_judged_before_independence() {
        let item = Item::review(
            "adversarial-review",
            ".agents/skills/adversarial-review/SKILL.md",
            Independence { different_session: true, different_model: true },
            Severity::P1,
        );
        let loaded = policy(vec![item]);
        let failed = decide(&loaded, &[review_record("implementer", "model-a", vec![finding(Severity::P1)])]);
        assert_eq!(failed.decision, DecisionName::Rejected);
        assert_eq!(failed.items[0].message, "finding at P1 meets failOn P1");
        let blocked = decide(&loaded, &[review_record("implementer", "model-b", vec![finding(Severity::P3)])]);
        assert_eq!(blocked.items[0].state, ItemState::Independence);
        assert_eq!(blocked.items[0].message, "reviewer does not satisfy differentSession");
        let unknown = decide(&loaded, &[review_record("reviewer", "", vec![finding(Severity::P2)])]);
        assert_eq!(unknown.items[0].message, "reviewer does not satisfy differentModel");
        let passed = decide(&loaded, &[review_record("reviewer", "model-b", vec![finding(Severity::P2)])]);
        assert_eq!(passed.decision, DecisionName::Accepted);
        assert_eq!(passed.items[0].message, "review findings satisfy the policy");
    }

    #[test]
    fn blocked_wins_over_a_failed_requirement() {
        let loaded = policy(vec![
            Item::command("check", vec!["true".to_string()], 30),
            Item::unsupported("ci", "ci"),
        ]);
        let failed = command_record(&["true"], Some(1), false, false, false);
        let decision = decide(&loaded, &[failed]);
        assert_eq!(decision.decision, DecisionName::Blocked);
        assert_eq!(decision.items[1].message, "kind ci is not supported");
    }

    #[test]
    fn absent_policy_is_accepted() {
        let loaded = ResolvedPolicy {
            absent: true,
            retry: None,
            path: None,
            digest: None,
            files: Vec::new(),
            setup: Vec::new(),
            items: Vec::new(),
            warnings: Vec::new(),
        };
        let decision = decide(&loaded, &[]);
        assert_eq!(decision.decision, DecisionName::Accepted);
        assert_eq!(decision.message.as_deref(), Some("no closeout policy"));
    }

    #[test]
    fn path_scope_skips_before_evidence_and_unsupported() {
        let engine = Item::command("engine", vec!["false".to_string()], 30).with_paths(vec!["apps/engine/**".to_string()]);
        let always = Item::command("always", vec!["true".to_string()], 30);
        let loaded = policy(vec![engine, always]);
        let empty = Vec::new();
        let decision = decide_scoped(&loaded, &[], Some(&empty));
        assert_eq!(decision.items[0].state, ItemState::Skipped);
        assert_eq!(decision.items[0].message, "no changed path matches");
        assert_eq!(decision.items[1].state, ItemState::Missing);
        assert_eq!(decision.decision, DecisionName::Blocked);

        let changed = vec!["apps/engine/main.ts".to_string()];
        let mut failed = command_record(&["false"], Some(1), false, false, false);
        if let EvidenceRecord::Command(record) = &mut failed {
            record.item_id = "engine".to_string();
        }
        let ignored = decide_scoped(&loaded, &[failed.clone()], Some(&empty));
        assert_eq!(ignored.items[0].state, ItemState::Skipped);
        let matched = decide_scoped(&policy(vec![Item::command("engine", vec!["false".to_string()], 30).with_paths(vec!["apps/engine/**".to_string()])]), &[failed], Some(&changed));
        assert_eq!(matched.items[0].state, ItemState::Failed);
        assert_eq!(matched.decision, DecisionName::Rejected);

        let unsupported = policy(vec![Item::unsupported("ci", "ci").with_paths(vec!["apps/engine/**".to_string()])]);
        let skipped = decide_scoped(&unsupported, &[], Some(&empty));
        assert_eq!(skipped.items[0].state, ItemState::Skipped);
        assert_eq!(skipped.decision, DecisionName::Accepted);
        let blocking = decide_scoped(&unsupported, &[], Some(&changed));
        assert_eq!(blocking.items[0].state, ItemState::Unsupported);
        assert_eq!(blocking.decision, DecisionName::Blocked);
        let unavailable = decide(&unsupported, &[]);
        assert_eq!(unavailable.items[0].state, ItemState::Invalid);
        assert_eq!(unavailable.items[0].message, "changed paths are unavailable");
    }

    #[test]
    fn a_failed_setup_step_skips_a_missing_command() {
        let mut loaded = policy(vec![Item::command("check", vec!["false".to_string()], 30)]);
        loaded.setup = vec![Item::setup("install", vec!["false".to_string()], 30)];
        let waiting = decide(&loaded, &[]);
        assert_eq!(waiting.items[0].state, ItemState::Missing);
        assert_eq!(waiting.items[1].state, ItemState::Missing);
        assert_eq!(waiting.decision, DecisionName::Blocked);

        let mut failed = command_record(&["false"], Some(1), false, false, false);
        if let EvidenceRecord::Command(record) = &mut failed {
            record.item_id = "install".to_string();
        }
        let decision = decide(&loaded, &[failed]);
        assert_eq!(decision.decision, DecisionName::Rejected);
        assert_eq!(decision.items[0].state, ItemState::Failed);
        assert_eq!(decision.items[0].kind, "setup");
        assert_eq!(decision.items[1].state, ItemState::Skipped);
        loaded.retry = Some(crate::types::RetryPolicy { max_failed_attempts_per_item: 1, scope: RetryScope::Candidate });
        let mut failed = command_record(&["false"], Some(1), false, false, false);
        if let EvidenceRecord::Command(record) = &mut failed {
            record.item_id = "install".to_string();
        }
        let exhausted = decide(&loaded, &[failed]);
        assert_eq!(exhausted.items[0].state, ItemState::Exhausted);
        assert_eq!(exhausted.items[1].state, ItemState::Skipped);
        assert_eq!(decision.items[1].message, "setup failed");

        let mut dirty = command_record(&["false"], Some(0), false, true, false);
        if let EvidenceRecord::Command(record) = &mut dirty {
            record.item_id = "install".to_string();
            record.exec.argv = vec!["false".to_string()];
        }
        let passed = decide(&loaded, &[dirty]);
        assert_eq!(passed.items[0].state, ItemState::Passed);
        assert_eq!(passed.items[0].message, "exited 0");
        assert_eq!(passed.items[1].state, ItemState::Missing);
        assert_eq!(passed.decision, DecisionName::Blocked);
    }
}
