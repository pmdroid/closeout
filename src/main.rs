use clap::{Args, Parser, Subcommand};
use closeout::{
    blocked_policy, check_decision, check_evidence, decision_from_markdown, evaluate, exit_status, format_decision,
    format_markdown, generate_pgp_keys, load_policy, load_policy_from_origin, next_attempt, open_report, read_evidence,
    changed_scope, resolve_commit, run_commands,
    seal_report, write_decision_file, write_record, Candidate, Decision, EvidenceRecord, EvaluateInput, Gate, ItemBody,
    LoadResult, RunInput, PRODUCER_NAME, SPEC_VERSION, VERSION,
};
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const USAGE: &str = "\
closeout validate [--root dir] [--json]
closeout run --gate beforePR --base rev --head rev [--root dir] [--evidence-dir dir] [--json]
closeout run --gate beforePR --base rev --head rev --format markdown --pgp-key <public-key> [--root dir] [--evidence-dir dir]
closeout decision --gate beforePR --base rev --head rev [--root dir] [--evidence-dir dir] [--json]
closeout try --gate beforePR --base rev --head rev [--root dir] [--json]
closeout verify --pgp-key <private-key> --head <commit> [--require-accepted] <report>
closeout keygen --pgp --out <dir>
closeout evidence add --gate beforePR --item id --base rev --head rev --session id --model id --findings file [--provider id]";

#[derive(Parser)]
#[command(name = "closeout", override_usage = USAGE, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Validate(Flags),
    Run(Flags),
    Decision(Flags),
    Try(Flags),
    Verify(VerifyFlags),
    Keygen(KeygenFlags),
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
}

#[derive(Subcommand)]
enum EvidenceAction {
    Add(AddFlags),
}

#[derive(Args)]
struct Flags {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    gate: Option<String>,
    #[arg(long)]
    base: Option<String>,
    #[arg(long)]
    head: Option<String>,
    #[arg(long = "evidence-dir")]
    evidence_dir: Option<PathBuf>,
    #[arg(long = "candidate-session")]
    candidate_session: Option<String>,
    #[arg(long = "candidate-model")]
    candidate_model: Option<String>,
    #[arg(long = "candidate-provider")]
    candidate_provider: Option<String>,
    #[arg(long)]
    format: Option<OutputFormat>,
    #[arg(long = "pgp-key")]
    pgp_key: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Markdown,
}

#[derive(Args)]
struct VerifyFlags {
    #[arg(long = "pgp-key")]
    pgp_key: PathBuf,
    #[arg(long)]
    head: String,
    #[arg(long = "require-accepted")]
    require_accepted: bool,
    report: PathBuf,
}

#[derive(Args)]
struct KeygenFlags {
    #[arg(long)]
    pgp: bool,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct AddFlags {
    #[command(flatten)]
    flags: Flags,
    #[arg(long)]
    item: Option<String>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    findings: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(message) = dispatch(cli) {
        eprintln!("{message}");
        process::exit(3);
    }
}

fn dispatch(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Validate(flags) => validate(&flags),
        Command::Run(flags) => run(&flags),
        Command::Decision(flags) => decision(&flags),
        Command::Try(flags) => trial(&flags),
        Command::Verify(flags) => verify(&flags),
        Command::Keygen(flags) => keygen(&flags),
        Command::Evidence { action: EvidenceAction::Add(flags) } => evidence_add(&flags),
    }
}

fn validate(flags: &Flags) -> Result<(), String> {
    reject_seal_flags(flags);
    let root = resolve_root(&flags.root);
    match load_policy_from_origin(&root) {
        LoadResult::Failed { message, warnings, .. } => {
            let mut blocked = blocked_policy(&message, Gate::BeforePr, candidate_from(flags));
            blocked.warnings = warnings;
            emit(&blocked, flags.json);
        }
        LoadResult::Ready(policy) => {
            for warning in &policy.warnings {
                eprintln!("{}", warning.message);
            }
            if flags.json {
                let report = json!({
                    "specVersion": SPEC_VERSION,
                    "ok": true,
                    "absent": policy.absent,
                    "legacy": policy.legacy,
                    "path": policy.path,
                    "digest": policy.digest,
                    "items": policy.items.iter().map(|item| &item.id).collect::<Vec<_>>(),
                    "warnings": policy.warnings,
                });
                println!("{}", serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?);
            } else if policy.absent {
                println!("no closeout policy");
            } else {
                let mut lines = vec![policy.path.unwrap_or_default(), policy.digest.unwrap_or_default()];
                lines.extend(policy.items.into_iter().map(|item| item.id));
                println!("{}", lines.join("\n"));
            }
            Ok(())
        }
    }
}

fn run(flags: &Flags) -> Result<(), String> {
    let format = flags.format.unwrap_or(OutputFormat::Text);
    if flags.json && format == OutputFormat::Markdown {
        fail_usage("--format markdown cannot be combined with --json");
    }
    if format == OutputFormat::Markdown && flags.pgp_key.is_none() {
        fail_usage("missing --pgp-key");
    }
    if format == OutputFormat::Text && flags.pgp_key.is_some() {
        fail_usage("--pgp-key requires --format markdown");
    }
    let gate = gate_from(&flags.gate);
    let base_rev = require_rev("base", &flags.base);
    let head_rev = require_rev("head", &flags.head);
    let root = resolve_root(&flags.root);
    let candidate = candidate_from(flags);
    let policy = match load_policy_from_origin(&root) {
        LoadResult::Failed { message, warnings, .. } => {
            let mut blocked = blocked_policy(&message, gate, candidate);
            blocked.warnings = warnings;
            emit(&blocked, flags.json);
        }
        LoadResult::Ready(policy) => policy,
    };
    let dir = evidence_dir(&root, &flags.evidence_dir);
    let decision = run_commands(&RunInput {
        root,
        policy,
        gate,
        base_rev,
        head_rev,
        candidate,
        evidence_dir: dir.clone(),
    })?;
    if let Some(digest) = &decision.policy.digest {
        write_decision_file(&dir, gate.as_str(), digest, &decision.head, &decision)?;
    }
    if format == OutputFormat::Markdown {
        emit_sealed(&decision, flags.pgp_key.as_deref().unwrap());
    }
    emit(&decision, flags.json);
}

fn decision(flags: &Flags) -> Result<(), String> {
    reject_seal_flags(flags);
    let gate = gate_from(&flags.gate);
    let base_rev = require_rev("base", &flags.base);
    let head_rev = require_rev("head", &flags.head);
    let root = resolve_root(&flags.root);
    let candidate = candidate_from(flags);
    let policy = match load_policy_from_origin(&root) {
        LoadResult::Failed { message, warnings, .. } => {
            let mut blocked = blocked_policy(&message, gate, candidate);
            blocked.warnings = warnings;
            emit(&blocked, flags.json);
        }
        LoadResult::Ready(policy) => policy,
    };
    let dir = evidence_dir(&root, &flags.evidence_dir);
    let base = resolve_commit(&root, &base_rev);
    let head = resolve_commit(&root, &head_rev);
    if base.is_none() || head.is_none() {
        emit(&evaluate(EvaluateInput {
            policy: &policy,
            gate,
            base: base.as_deref().unwrap_or(""),
            head: head.as_deref().unwrap_or(""),
            candidate: &candidate,
            records: &[],
            changed_paths: None,
            evidence_error: Some("base or head does not resolve to a commit".to_string()),
        }), flags.json);
    }
    let base = base.unwrap_or_default();
    let head = head.unwrap_or_default();
    let records = match read_evidence(&dir) {
        Ok(records) => records,
        Err(message) => emit(
            &evaluate(EvaluateInput {
                policy: &policy,
                gate,
                base: &base,
                head: &head,
                candidate: &candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some(message),
            }),
            flags.json,
        ),
    };
    let changed = match changed_scope(&root, &policy, gate, &base, &head) {
        Ok(paths) => paths,
        Err(message) => emit(
            &evaluate(EvaluateInput {
                policy: &policy,
                gate,
                base: &base,
                head: &head,
                candidate: &candidate,
                records: &[],
                changed_paths: None,
                evidence_error: Some(message),
            }),
            flags.json,
        ),
    };
    let decision = evaluate(EvaluateInput {
        policy: &policy,
        gate,
        base: &base,
        head: &head,
        candidate: &candidate,
        records: &records,
        changed_paths: changed.as_deref(),
        evidence_error: None,
    });
    if let Some(digest) = &decision.policy.digest {
        write_decision_file(&dir, gate.as_str(), digest, &decision.head, &decision)?;
    }
    emit(&decision, flags.json);
}

fn evidence_add(flags: &AddFlags) -> Result<(), String> {
    reject_seal_flags(&flags.flags);
    let gate = gate_from(&flags.flags.gate);
    let item_id = require_text("item", &flags.item);
    let session = require_text("session", &flags.session);
    let model = require_text("model", &flags.model);
    let findings_path = match &flags.findings {
        Some(path) if !path.as_os_str().is_empty() => path.clone(),
        _ => fail_usage("missing --findings"),
    };
    let base_rev = require_rev("base", &flags.flags.base);
    let head_rev = require_rev("head", &flags.flags.head);
    let root = resolve_root(&flags.flags.root);
    let policy = match load_policy_from_origin(&root) {
        LoadResult::Failed { message, .. } => {
            eprintln!("{message}");
            process::exit(3);
        }
        LoadResult::Ready(policy) => policy,
    };
    if !policy.items.iter().any(|item| item.id == item_id && item.gate == gate && matches!(item.body, ItemBody::Review { .. })) {
        fail_usage(&format!("no review requirement {item_id} at {}", gate.as_str()));
    }
    let Some(digest) = policy.digest.clone() else {
        eprintln!("base or head does not resolve to a commit");
        process::exit(3);
    };
    let Some(base) = resolve_commit(&root, &base_rev) else {
        eprintln!("base or head does not resolve to a commit");
        process::exit(3);
    };
    let Some(head) = resolve_commit(&root, &head_rev) else {
        eprintln!("base or head does not resolve to a commit");
        process::exit(3);
    };
    let text = match fs::read_to_string(&findings_path) {
        Ok(text) => text,
        Err(_) => fail_usage("findings file is not JSON"),
    };
    let findings: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => fail_usage("findings file is not JSON"),
    };
    if !findings.is_array() {
        fail_usage("findings file must be a JSON array");
    }
    let dir = evidence_dir(&root, &flags.flags.evidence_dir);
    let existing = match read_evidence(&dir) {
        Ok(records) => records,
        Err(message) => {
            eprintln!("{message}");
            process::exit(3);
        }
    };
    let record = json!({
        "specVersion": SPEC_VERSION,
        "recordType": "review",
        "itemId": item_id,
        "base": base,
        "head": head,
        "policyDigest": digest,
        "attempt": next_attempt(&existing, &item_id, &base, &head, &digest),
        "evaluator": {"name": PRODUCER_NAME, "version": VERSION},
        "producer": {
            "session": session,
            "model": model,
            "provider": flags.provider.clone().unwrap_or_default(),
        },
        "findings": findings,
        "artifacts": [],
    });
    if let Err(message) = check_evidence(&record) {
        eprintln!("findings are invalid: {message}");
        process::exit(3);
    }
    let typed: EvidenceRecord = serde_json::from_value(record.clone()).map_err(|err| err.to_string())?;
    write_record(&dir, &typed)?;
    for warning in &policy.warnings {
        eprintln!("{}", warning.message);
    }
    println!("{}", serde_json::to_string_pretty(&record).map_err(|err| err.to_string())?);
    Ok(())
}

fn trial(flags: &Flags) -> Result<(), String> {
    reject_seal_flags(flags);
    let gate = gate_from(&flags.gate);
    let base_rev = require_rev("base", &flags.base);
    let head_rev = require_rev("head", &flags.head);
    let root = resolve_root(&flags.root);
    let candidate = candidate_from(flags);
    let home = home_dir()?;
    eprintln!("local trial from ~/.agents/closeout.yaml is not acceptance");
    let policy = match load_policy(&home) {
        LoadResult::Failed { message, warnings, .. } => {
            let mut blocked = blocked_policy(&message, gate, candidate);
            blocked.warnings = warnings;
            emit(&blocked, flags.json);
        }
        LoadResult::Ready(policy) if policy.absent => {
            emit(
                &blocked_policy("no closeout policy in ~/.agents/closeout.yaml", gate, candidate),
                flags.json,
            );
        }
        LoadResult::Ready(policy) => policy,
    };
    let scratch = Scratch::new();
    let decision = run_commands(&RunInput {
        root,
        policy,
        gate,
        base_rev,
        head_rev,
        candidate,
        evidence_dir: scratch.path.clone(),
    });
    drop(scratch);
    emit(&decision?, flags.json);
}

fn home_dir() -> Result<PathBuf, String> {
    match env::var_os("HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home)),
        _ => Err("HOME is unset".to_string()),
    }
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("closeout-trial-{}-{nanos}", std::process::id()));
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn verify(flags: &VerifyFlags) -> Result<(), String> {
    if flags.head.is_empty() {
        fail_usage("missing --head");
    }
    let private_key = fs::read_to_string(&flags.pgp_key).map_err(|_| "private key is unreadable".to_string())?;
    let armor = fs::read_to_string(&flags.report).map_err(|_| "sealed report is unreadable".to_string())?;
    let body = open_report(&private_key, &armor)?;
    let decision = decision_from_markdown(&body)?;
    if decision.head != flags.head {
        return Err("head does not match the sealed report".to_string());
    }
    for warning in &decision.warnings {
        eprintln!("{}", warning.message);
    }
    print!("{}", format_decision(&decision));
    let status = if flags.require_accepted { exit_status(&decision) } else { 0 };
    process::exit(status);
}

fn keygen(flags: &KeygenFlags) -> Result<(), String> {
    if !flags.pgp {
        fail_usage("missing --pgp");
    }
    fs::create_dir_all(&flags.out).map_err(|_| format!("cannot write {}", flags.out.display()))?;
    let (public_armor, private_armor) = generate_pgp_keys()?;
    let public_path = flags.out.join("closeout-public.asc");
    let private_path = flags.out.join("closeout-private.asc");
    fs::write(&public_path, public_armor).map_err(|_| format!("cannot write {}", public_path.display()))?;
    write_private(&private_path, &private_armor)?;
    println!("{}", public_path.display());
    println!("{}", private_path.display());
    Ok(())
}

fn emit_sealed(decision: &Decision, pgp_key: &Path) -> ! {
    let value = serde_json::to_value(decision).unwrap_or(Value::Null);
    if let Err(message) = check_decision(&value) {
        eprintln!("decision document is invalid: {message}");
        process::exit(3);
    }
    let public_key = match fs::read_to_string(pgp_key) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("public key is unreadable");
            process::exit(3);
        }
    };
    let body = match format_markdown(decision) {
        Ok(body) => body,
        Err(message) => {
            eprintln!("{message}");
            process::exit(3);
        }
    };
    let armor = match seal_report(&public_key, &body) {
        Ok(armor) => armor,
        Err(message) => {
            eprintln!("{message}");
            process::exit(3);
        }
    };
    for warning in &decision.warnings {
        eprintln!("{}", warning.message);
    }
    println!("{armor}");
    process::exit(exit_status(decision));
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| format!("cannot write {}", path.display()))?;
    file.write_all(text.as_bytes()).map_err(|_| format!("cannot write {}", path.display()))?;
    Ok(())
}

fn reject_seal_flags(flags: &Flags) {
    if flags.format.is_some() || flags.pgp_key.is_some() {
        fail_usage("--format and --pgp-key are only valid on run");
    }
}

fn emit(decision: &Decision, json: bool) -> ! {
    let value = serde_json::to_value(decision).unwrap_or(Value::Null);
    if let Err(message) = check_decision(&value) {
        eprintln!("decision document is invalid: {message}");
        process::exit(3);
    }
    for warning in &decision.warnings {
        eprintln!("{}", warning.message);
    }
    if json {
        match serde_json::to_string_pretty(&value) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("{err}");
                process::exit(3);
            }
        }
    } else {
        print!("{}", format_decision(decision));
    }
    process::exit(exit_status(decision));
}

fn candidate_from(flags: &Flags) -> Candidate {
    Candidate {
        session: flags.candidate_session.clone().unwrap_or_default(),
        model: flags.candidate_model.clone().unwrap_or_default(),
        provider: flags.candidate_provider.clone().unwrap_or_default(),
    }
}

fn gate_from(flag: &Option<String>) -> Gate {
    if flag.as_deref() != Some("beforePR") {
        fail_usage("gate must be beforePR");
    }
    Gate::BeforePr
}

fn evidence_dir(root: &Path, requested: &Option<PathBuf>) -> PathBuf {
    match requested {
        None => root.join(".closeout"),
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => root.join(path),
    }
}

fn resolve_root(flag: &Option<PathBuf>) -> PathBuf {
    let raw = flag.clone().unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    std::path::absolute(&raw).unwrap_or(raw)
}

fn require_rev(name: &str, value: &Option<String>) -> String {
    match value {
        Some(value) if !value.is_empty() => value.clone(),
        _ => fail_usage(&format!("missing --{name}")),
    }
}

fn require_text(name: &str, value: &Option<String>) -> String {
    match value {
        Some(value) if !value.is_empty() => value.clone(),
        _ => fail_usage(&format!("missing --{name}")),
    }
}

fn fail_usage(message: &str) -> ! {
    eprintln!("{message}\n{USAGE}");
    process::exit(2);
}
