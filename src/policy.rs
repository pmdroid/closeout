use crate::canonical::{digest_of, sha256_hex, utf16_cmp};
use crate::git::Located;
use crate::paths::{check_path_patterns, is_slug, repo_path, to_posix};
use crate::schema::check_policy;
use crate::types::{Item, ItemBody, LoadResult, PolicyFile, ResolvedPolicy, RetryPolicy, Warning, PUBLIC_POLICY_PATH, SPEC_VERSION};
use crate::yaml_doc::read_yaml_file;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const STAGING_PREFIX: &str = "closeout-policy-";
const STAGING_MARKER: &str = ".closeout-staging";

#[derive(Deserialize)]
struct PublicDocument {
    retry: Option<RetryPolicy>,
    #[serde(default)]
    imports: Vec<PublicImport>,
    #[serde(default)]
    items: Vec<PublicItem>,
    #[serde(default)]
    setup: Vec<SetupStep>,
}

#[derive(Deserialize)]
struct SetupStep {
    id: String,
    exec: Vec<String>,
    #[serde(rename = "timeoutSeconds")]
    timeout_seconds: u64,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct PublicImport {
    path: String,
    #[serde(rename = "as")]
    name: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
enum PublicItem {
    #[serde(rename = "command")]
    Command {
        id: String,
        exec: Vec<String>,
        #[serde(rename = "timeoutSeconds")]
        timeout_seconds: u64,
        #[serde(default)]
        paths: Vec<String>,
    },
    #[serde(rename = "review")]
    Review {
        id: String,
        skill: String,
        independence: crate::types::Independence,
        #[serde(rename = "failOn")]
        fail_on: crate::types::Severity,
        #[serde(default)]
        paths: Vec<String>,
    },
}

impl PublicItem {
    fn id(&self) -> &str {
        match self {
            Self::Command { id, .. } | Self::Review { id, .. } => id,
        }
    }
}

pub fn load_policy_from_origin(root: &Path) -> LoadResult {
    let commit = match crate::git::origin_main(root) {
        Ok(commit) => commit,
        Err(message) => return invalid(&message),
    };
    let staged = match stage_origin_policy(root, &commit) {
        Ok(staged) => staged,
        Err(message) => return invalid(&message),
    };
    match load_policy(&staged.tree) {
        LoadResult::Ready(policy) if policy.absent => load_global_policy(),
        other => other,
    }
}

fn load_global_policy() -> LoadResult {
    let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) else {
        return invalid("HOME is unset");
    };
    match load_policy(&PathBuf::from(home)) {
        LoadResult::Ready(policy) if policy.absent => LoadResult::Ready(policy),
        LoadResult::Ready(mut policy) => {
            let shown = match policy.path.as_deref() {
                Some(path) => format!("~/{path}"),
                None => "~/.agents/closeout.yaml".to_string(),
            };
            policy.warnings.insert(
                0,
                Warning {
                    code: "global-policy".to_string(),
                    message: format!("Using {shown} because origin/main has no closeout policy."),
                },
            );
            policy.path = Some(shown);
            LoadResult::Ready(policy)
        }
        other => other,
    }
}

pub fn load_policy(root: &Path) -> LoadResult {
    let abs = match fs::canonicalize(root) {
        Ok(path) if path.is_dir() => path,
        _ => return invalid("policy root is not a directory"),
    };
    let public_file = abs.join(PUBLIC_POLICY_PATH);
    let has_public = match entry_on_disk(&public_file) {
        Ok(present) => present,
        Err(message) => return invalid(&message),
    };
    if !has_public {
        return LoadResult::Ready(ResolvedPolicy {
            absent: true,
            retry: None,
            path: None,
            digest: None,
            files: Vec::new(),
            setup: Vec::new(),
            items: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let mut setup = Vec::new();
    let mut retry = None;
    let mut items = Vec::new();
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut ids = HashSet::new();
    if let Err(message) = walk(&abs, PUBLIC_POLICY_PATH, "", &[], &mut seen, &mut retry, &mut setup, &mut items, &mut files, &mut ids) {
        return invalid(&message);
    }
    match skill_hashes(&abs, &items) {
        Ok(skill_files) => files.extend(skill_files),
        Err(message) => return invalid(&message),
    }
    match finish(PUBLIC_POLICY_PATH, retry, unique_files(files), setup, items, Vec::new()) {
        Ok(policy) => LoadResult::Ready(policy),
        Err(message) => invalid(&message),
    }
}

pub fn canonical_policy_body(policy: &ResolvedPolicy) -> Result<String, String> {
    crate::canonical::canonical_json(&policy_value(policy.retry.as_ref(), &policy.files, &policy.setup, &policy.items))
}

fn policy_value(retry: Option<&RetryPolicy>, files: &[PolicyFile], setup: &[Item], items: &[Item]) -> Value {
    let mut body = json!({
        "specVersion": SPEC_VERSION,
        "files": files,
        "items": items.iter().map(canonical_item).collect::<Vec<_>>(),
    });
    if let Some(retry) = retry {
        body["retry"] = json!(retry);
    }
    if !setup.is_empty() {
        if let Value::Object(map) = &mut body {
            map.insert("setup".to_string(), json!(setup.iter().map(canonical_item).collect::<Vec<_>>()));
        }
    }
    body
}

fn finish(
    path: &str,
    retry: Option<RetryPolicy>,
    mut files: Vec<PolicyFile>,
    setup: Vec<Item>,
    items: Vec<Item>,
    warnings: Vec<Warning>,
) -> Result<ResolvedPolicy, String> {
    files.sort_by(|left, right| utf16_cmp(&left.path, &right.path));
    let body = policy_value(retry.as_ref(), &files, &setup, &items);
    Ok(ResolvedPolicy {
        absent: false,
        retry,
        path: Some(path.to_string()),
        digest: Some(digest_of(&body)?),
        files,
        setup,
        items,
        warnings,
    })
}

fn canonical_item(item: &Item) -> Value {
    let mut value = match &item.body {
        ItemBody::Unsupported { kind } => json!({
            "id": item.id,
            "kind": kind,
            "gate": item.gate.as_str(),
            "supported": false,
        }),
        ItemBody::Command { exec, timeout_seconds } | ItemBody::Setup { exec, timeout_seconds } => json!({
            "id": item.id,
            "kind": item.kind_name(),
            "gate": item.gate.as_str(),
            "exec": exec,
            "timeoutSeconds": timeout_seconds,
        }),
        ItemBody::Review {
            skill,
            independence,
            fail_on,
        } => {
            let mut flags = serde_json::Map::new();
            flags.insert("differentModel".to_string(), json!(independence.different_model));
            flags.insert("differentSession".to_string(), json!(independence.different_session));
            json!({
                "id": item.id,
                "kind": "review",
                "gate": item.gate.as_str(),
                "skill": skill,
                "independence": Value::Object(flags),
                "failOn": fail_on,
            })
        }
    };
    if !item.paths.is_empty() {
        if let Value::Object(map) = &mut value {
            map.insert("paths".to_string(), json!(item.paths));
        }
    }
    value
}

fn walk(
    root: &Path,
    path: &str,
    prefix: &str,
    stack: &[PathBuf],
    seen_files: &mut HashSet<String>,
    retry: &mut Option<RetryPolicy>,
    setup: &mut Vec<Item>,
    items: &mut Vec<Item>,
    files: &mut Vec<PolicyFile>,
    ids: &mut HashSet<String>,
) -> Result<(), String> {
    let safe = repo_path(root, path).ok_or_else(|| format!("import path is not repository-relative: {path}"))?;
    let absolute = root.join(&safe);
    if stack.iter().any(|entry| entry == &absolute) {
        let mut chain: Vec<&Path> = stack.iter().map(PathBuf::as_path).collect();
        chain.push(&absolute);
        let rendered = chain.iter().map(|entry| rel_posix(root, entry)).collect::<Vec<_>>().join(" -> ");
        return Err(format!("import cycle: {rendered}"));
    }
    let file_meta = fs::metadata(&absolute).ok();
    if !file_meta.as_ref().is_some_and(|meta| meta.is_file()) {
        return Err(format!("import is missing: {safe}"));
    }
    let value = read_yaml_file(&absolute).map_err(|message| format!("{safe}: {message}"))?;
    check_policy(&value).map_err(|message| format!("{safe}: {message}"))?;
    let document: PublicDocument = serde_json::from_value(value).map_err(|err| format!("{safe}: {err}"))?;
    if !prefix.is_empty() && document.retry.is_some() {
        return Err("retry is only allowed on the entry policy".to_string());
    }
    if prefix.is_empty() {
        *retry = document.retry;
    }
    if !prefix.is_empty() && !document.setup.is_empty() {
        return Err("setup is only allowed on the entry policy".to_string());
    }
    if seen_files.insert(safe.clone()) {
        files.push(file_hash(root, &safe)?);
    }
    let mut names = HashSet::new();
    let mut child_stack = stack.to_vec();
    child_stack.push(absolute);
    for entry in &document.imports {
        if !names.insert(entry.name.clone()) {
            return Err(format!("duplicate import name {} in {safe}", entry.name));
        }
        let child_prefix = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        walk(root, &entry.path, &child_prefix, &child_stack, seen_files, retry, setup, items, files, ids)?;
    }
    if prefix.is_empty() {
        for step in &document.setup {
            if !is_slug(&step.id) {
                return Err(format!("invalid id {}", step.id));
            }
            if !ids.insert(step.id.clone()) {
                return Err(format!("duplicate requirement id {}", step.id));
            }
            let mut item = Item::setup(step.id.clone(), step.exec.clone(), step.timeout_seconds);
            item.paths = check_path_patterns(&step.paths)?;
            setup.push(item);
        }
    }
    for raw in &document.items {
        let local = raw.id();
        if !is_slug(local) {
            return Err(format!("invalid id {local}"));
        }
        let id = if prefix.is_empty() { local.to_string() } else { format!("{prefix}/{local}") };
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate requirement id {id}"));
        }
        match raw {
            PublicItem::Command {
                exec,
                timeout_seconds,
                paths,
                ..
            } => {
                let mut item = Item::command(id, exec.clone(), *timeout_seconds);
                item.paths = check_path_patterns(paths)?;
                items.push(item);
            }
            PublicItem::Review {
                skill,
                independence,
                fail_on,
                paths,
                ..
            } => {
                let Some(skill_path) = repo_path(root, skill).filter(|candidate| candidate.ends_with("/SKILL.md")) else {
                    return Err(format!("skill path is not a repository SKILL.md: {skill}"));
                };
                let skill_file = root.join(&skill_path);
                if !fs::metadata(&skill_file).is_ok_and(|meta| meta.is_file()) {
                    return Err(format!("skill is missing: {skill_path}"));
                }
                let mut item = Item::review(id, skill_path, independence.clone(), *fail_on);
                item.paths = check_path_patterns(paths)?;
                items.push(item);
            }
        }
    }
    Ok(())
}

fn skill_hashes(root: &Path, items: &[Item]) -> Result<Vec<PolicyFile>, String> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        let ItemBody::Review { skill, .. } = &item.body else {
            continue;
        };
        let Some(skill_path) = repo_path(root, skill).filter(|candidate| candidate.ends_with("/SKILL.md")) else {
            continue;
        };
        let skill_file = root.join(&skill_path);
        if !fs::metadata(&skill_file).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        let Some(dir) = skill_file.parent() else {
            continue;
        };
        for absolute in list_files(dir)? {
            let rel = rel_posix(root, &absolute);
            if !seen.insert(rel.clone()) {
                continue;
            }
            files.push(file_hash(root, &rel)?);
        }
    }
    Ok(files)
}

fn list_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    let mut found = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), Vec::new())];
    while let Some((current, mut entered)) = stack.pop() {
        let real = fs::canonicalize(&current).map_err(|_| "could not read the skill directory".to_string())?;
        if entered.contains(&real) {
            return Err(format!("symlink loop: {}", current.display()));
        }
        let entries = fs::read_dir(&current)
            .and_then(|listing| listing.collect::<Result<Vec<_>, _>>())
            .map_err(|_| "could not read the skill directory".to_string())?;
        let staging = real.parent() == Some(temp.as_path())
            && real.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with(STAGING_PREFIX))
            && entries.iter().any(|entry| entry.file_name() == STAGING_MARKER);
        if staging {
            return Err(format!(
                "skill directory holds closeout staging output at {}; set TMPDIR outside skill directories",
                current.display()
            ));
        }
        entered.push(real);
        for entry in entries {
            let absolute = entry.path();
            if entry.file_name().to_str().is_none() {
                return Err(format!("skill file name is not UTF-8: {}", absolute.display()));
            }
            let meta = fs::metadata(&absolute).map_err(|_| format!("symlink is broken: {}", absolute.display()))?;
            if meta.is_dir() {
                stack.push((absolute, entered.clone()));
            } else if meta.is_file() {
                found.push(absolute);
            }
        }
    }
    Ok(found)
}

fn file_hash(root: &Path, relative_path: &str) -> Result<PolicyFile, String> {
    let bytes = fs::read(root.join(relative_path)).map_err(|_| "could not read the policy file".to_string())?;
    Ok(PolicyFile {
        path: relative_path.to_string(),
        sha256: sha256_hex(&bytes),
    })
}

fn unique_files(files: Vec<PolicyFile>) -> Vec<PolicyFile> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for file in files.into_iter().rev() {
        if seen.insert(file.path.clone()) {
            out.push(file);
        }
    }
    out.reverse();
    out
}

fn rel_posix(root: &Path, absolute: &Path) -> String {
    absolute.strip_prefix(root).map(to_posix).unwrap_or_else(|_| absolute.display().to_string())
}

struct Staged {
    path: PathBuf,
    tree: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn stage_origin_policy(repo: &Path, commit: &str) -> Result<Staged, String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or(0);
    let path = std::env::temp_dir().join(format!("{STAGING_PREFIX}{}-{n}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).map_err(|_| "could not read the policy file".to_string())?;
    let staged = Staged { tree: path.join("tree"), path };
    fs::write(staged.path.join(STAGING_MARKER), "").map_err(|_| "could not read the policy file".to_string())?;
    fs::create_dir(&staged.tree).map_err(|_| "could not read the policy file".to_string())?;
    let mut pending = vec![PUBLIC_POLICY_PATH.to_string()];
    let mut seen = HashSet::new();
    while let Some(relative) = pending.pop() {
        if !seen.insert(relative.clone()) {
            continue;
        }
        if repo_path(&staged.tree, &relative).is_none() {
            continue;
        }
        let Some(bytes) = read_located(repo, commit, &relative)? else {
            if relative == PUBLIC_POLICY_PATH && broken(repo, commit, &relative)? {
                return Err(format!("symlink is broken: {relative}"));
            }
            continue;
        };
        write_rel(&staged.tree, &relative, &bytes)?;
        if relative.ends_with("/SKILL.md") {
            if let Some(dir) = relative.rsplit_once('/').map(|(dir, _)| dir) {
                copy_tree(repo, commit, &staged.tree, dir, dir, &[])?;
            }
        }
        if !relative.ends_with("/SKILL.md") {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if let Ok(value) = crate::yaml_doc::read_yaml_value(text) {
                    enqueue_paths(&value, &mut pending);
                }
            }
        }
    }
    Ok(staged)
}

fn read_located(repo: &Path, commit: &str, relative: &str) -> Result<Option<Vec<u8>>, String> {
    match crate::git::locate(repo, commit, relative)? {
        Located::Missing => Ok(None),
        Located::Commit(entry) if regular_mode(&entry.mode) => crate::git::read_blob(repo, &entry.object).map(Some),
        Located::Commit(entry) if entry.mode == "040000" => Ok(None),
        Located::Commit(_) => Err(format!("policy path is not a file: {relative}")),
        Located::Disk(path) => match fs::metadata(&path) {
            Err(err) if nothing_there(&err) => Ok(None),
            Err(_) => Err(format!("could not read the policy file: {}", path.display())),
            Ok(meta) if meta.is_file() => read_disk(&path).map(Some),
            Ok(meta) if meta.is_dir() => Ok(None),
            Ok(_) => Err(format!("policy path is not a file: {relative}")),
        },
    }
}

fn broken(repo: &Path, commit: &str, relative: &str) -> Result<bool, String> {
    let Some((dir, name)) = relative.rsplit_once('/') else {
        return Ok(false);
    };
    match crate::git::locate(repo, commit, dir)? {
        Located::Commit(entry) => {
            let leaf = crate::git::tree_entry(repo, commit, &crate::git::child(&entry.path, name))?;
            Ok(leaf.is_some_and(|leaf| leaf.mode != "040000"))
        }
        Located::Disk(path) if fs::metadata(&path).is_err() => Ok(true),
        Located::Disk(path) => match fs::symlink_metadata(path.join(name)) {
            Ok(meta) => Ok(!meta.is_dir()),
            Err(err) if nothing_there(&err) => Ok(false),
            Err(_) => Err(format!("could not read the policy file: {}", path.join(name).display())),
        },
        Located::Missing => Ok(crate::git::tree_entry(repo, commit, dir)?.is_some()),
    }
}

fn entry_on_disk(path: &Path) -> Result<bool, String> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).is_ok() && fs::metadata(parent).is_err() {
            return Err(format!("symlink is broken: {}", parent.display()));
        }
    }
    on_disk(path)
}

fn on_disk(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if nothing_there(&err) => Ok(false),
        Err(_) => Err(format!("could not read the policy file: {}", path.display())),
    }
}

fn nothing_there(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

fn copy_tree(repo: &Path, commit: &str, dest: &Path, source: &str, target: &str, entered: &[String]) -> Result<(), String> {
    let entry = match crate::git::locate(repo, commit, source)? {
        Located::Commit(entry) => entry,
        Located::Disk(path) => return copy_disk(&path, dest, target),
        Located::Missing => return Err(format!("symlink is broken: {target}")),
    };
    if regular_mode(&entry.mode) {
        return write_rel(dest, target, &crate::git::read_blob(repo, &entry.object)?);
    }
    if entry.mode != "040000" {
        return Err(format!("skill path is not a file: {}", entry.path));
    }
    if entered.iter().any(|path| path == &entry.path) {
        return Err(format!("symlink loop: {target}"));
    }
    let mut chain = entered.to_vec();
    chain.push(entry.path.clone());
    let prefix = crate::git::child(&entry.path, "");
    for blob in crate::git::list_blobs(repo, commit, &entry.path)? {
        let rest = blob.path.strip_prefix(&prefix).ok_or_else(|| "could not read the policy file".to_string())?;
        let into = format!("{target}/{rest}");
        if blob.mode == "120000" {
            copy_tree(repo, commit, dest, &blob.path, &into, &chain)?;
        } else if regular_mode(&blob.mode) {
            write_rel(dest, &into, &crate::git::read_blob(repo, &blob.object)?)?;
        } else {
            return Err(format!("skill path is not a file: {}", blob.path));
        }
    }
    Ok(())
}

fn copy_disk(from: &Path, dest: &Path, target: &str) -> Result<(), String> {
    let meta = fs::metadata(from).map_err(|_| format!("symlink is broken: {target}"))?;
    if meta.is_file() {
        return write_rel(dest, target, &read_disk(from)?);
    }
    if !meta.is_dir() {
        return Ok(());
    }
    for file in list_files(from)? {
        let rest = file.strip_prefix(from).ok().and_then(Path::to_str).ok_or_else(|| format!("skill file name is not UTF-8: {}", file.display()))?;
        write_rel(dest, &format!("{target}/{rest}"), &read_disk(&file)?)?;
    }
    Ok(())
}

fn read_disk(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|_| "could not read the policy file".to_string())
}

fn enqueue_paths(value: &Value, pending: &mut Vec<String>) {
    if let Some(imports) = value.get("imports").and_then(Value::as_array) {
        for entry in imports {
            if let Some(path) = entry.get("path").and_then(Value::as_str) {
                pending.push(path.to_string());
            }
        }
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        for item in items {
            if let Some(skill) = item.get("skill").and_then(Value::as_str) {
                pending.push(skill.to_string());
            }
        }
    }
}

fn regular_mode(mode: &str) -> bool {
    mode == "100644" || mode == "100755"
}

fn write_rel(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let Some(safe) = repo_path(root, relative) else {
        return Err(format!("import path is not repository-relative: {relative}"));
    };
    let dest = root.join(safe);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|_| "could not read the policy file".to_string())?;
    }
    fs::write(dest, bytes).map_err(|_| "could not read the policy file".to_string())
}

fn invalid(message: &str) -> LoadResult {
    LoadResult::Failed {
        code: "policy-invalid",
        message: message.to_string(),
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_repository_resolves_cargo_requirements() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        match load_policy(&root) {
            LoadResult::Ready(policy) => {
                let ids: Vec<_> = policy.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>();
                assert_eq!(ids, ["testing/check", "testing/tests", "security/validate", "adversarial-review"]);
                assert!(policy.digest.as_deref().unwrap_or("").starts_with("sha256:"));
                assert!(policy.files.iter().any(|file| file.path.ends_with("references/rubric.md")));
                assert!(policy.items.iter().all(|item| item.paths.is_empty()));
                let body = canonical_policy_body(&policy).unwrap();
                assert!(!body.contains("\"paths\""));
                assert!(!body.contains("\"setup\""));
            }
            LoadResult::Failed { message, .. } => panic!("{message}"),
        }
    }

    #[test]
    fn retry_requires_an_explicit_entry_limit_and_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".agents/closeout")).unwrap();
        let path = root.join(PUBLIC_POLICY_PATH);
        for retry in [json!({}), json!({"scope": "task"}), json!({"maxFailedAttemptsPerItem": 1}), json!({"maxFailedAttemptsPerItem": 0, "scope": "task"}), json!({"maxFailedAttemptsPerItem": 1, "scope": "session"})] {
            fs::write(&path, json!({"specVersion": "0.1", "retry": retry}).to_string()).unwrap();
            assert!(matches!(load_policy(root), LoadResult::Failed { .. }));
        }
        let mut document = json!({"specVersion": "0.1", "retry": {"maxFailedAttemptsPerItem": 2, "scope": "task"}});
        fs::write(&path, document.to_string()).unwrap();
        let LoadResult::Ready(before) = load_policy(root) else { panic!("retry should load"); };
        document["retry"]["maxFailedAttemptsPerItem"] = json!(3);
        fs::write(&path, document.to_string()).unwrap();
        let LoadResult::Ready(after) = load_policy(root) else { panic!("retry should load"); };
        assert_ne!(before.digest, after.digest);
        let canonical: Value = serde_json::from_str(&canonical_policy_body(&after).unwrap()).unwrap();
        assert_eq!(canonical["retry"], document["retry"]);
        fs::write(root.join(".agents/closeout/child.yaml"), document.to_string()).unwrap();
        fs::write(&path, "specVersion: \"0.1\"\nimports:\n  - path: .agents/closeout/child.yaml\n    as: child\n").unwrap();
        let LoadResult::Failed { message, .. } = load_policy(root) else { panic!("imported retry should fail"); };
        assert_eq!(message, "retry is only allowed on the entry policy");
    }

    #[test]
    fn only_the_public_entry_is_loaded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".acpdash")).unwrap();
        fs::write(root.join(".acpdash/closeout.yaml"), "version: 1\nitems: []\n").unwrap();
        let LoadResult::Ready(policy) = load_policy(root) else {
            panic!("policy should load");
        };
        assert!(policy.absent);
        assert!(policy.warnings.is_empty());
        fs::create_dir_all(root.join(".agents")).unwrap();
        fs::write(root.join(".agents/closeout.yaml"), "specVersion: \"0.1\"\n").unwrap();
        let LoadResult::Ready(policy) = load_policy(root) else {
            panic!("public policy should load");
        };
        assert!(!policy.absent);
        assert_eq!(policy.path.as_deref(), Some(PUBLIC_POLICY_PATH));
        assert!(policy.warnings.is_empty());
    }

    #[test]
    fn optional_paths_load_and_escape_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".agents/skills/look")).unwrap();
        fs::write(root.join(".agents/skills/look/SKILL.md"), "look\n").unwrap();
        fs::write(
            root.join(".agents/closeout.yaml"),
            r#"specVersion: "0.1"
items:
  - id: engine
    kind: command
    gate: beforePR
    exec: ["true"]
    timeoutSeconds: 30
    paths: ["src/**", "apps/engine/"]
  - id: look
    kind: review
    gate: beforePR
    skill: .agents/skills/look/SKILL.md
    independence:
      differentSession: false
      differentModel: false
    failOn: P1
    paths: ["src/**"]
"#,
        )
        .unwrap();
        let policy = match load_policy(root) {
            LoadResult::Ready(policy) => policy,
            LoadResult::Failed { message, .. } => panic!("{message}"),
        };
        assert_eq!(policy.items[0].paths, ["src/**", "apps/engine/"]);
        assert_eq!(policy.items[1].paths, ["src/**"]);
        let body: Value = serde_json::from_str(&canonical_policy_body(&policy).unwrap()).unwrap();
        assert_eq!(body["items"][0]["paths"], json!(["src/**", "apps/engine/"]));

        fs::write(
            root.join(".agents/closeout.yaml"),
            "specVersion: \"0.1\"\nitems:\n  - id: engine\n    kind: command\n    gate: beforePR\n    exec: [\"true\"]\n    timeoutSeconds: 30\n    paths: [\"../secret\"]\n",
        )
        .unwrap();
        match load_policy(root) {
            LoadResult::Failed { message, .. } => assert!(message.contains("path pattern is invalid: ../secret"), "{message}"),
            LoadResult::Ready(_) => panic!("escape should fail"),
        }

        fs::write(
            root.join(".agents/closeout.yaml"),
            "specVersion: \"0.1\"\nitems:\n  - id: engine\n    kind: command\n    gate: beforePR\n    exec: [\"true\"]\n    timeoutSeconds: 30\n    paths: []\n",
        )
        .unwrap();
        assert!(matches!(load_policy(root), LoadResult::Failed { .. }));


    }

    #[test]
    fn setup_loads_on_the_entry_and_keeps_the_canonical_digest_stable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".agents/closeout")).unwrap();
        fs::write(
            root.join(".agents/closeout.yaml"),
            r#"specVersion: "0.1"
setup:
  - id: js
    exec: ["bun", "install"]
    timeoutSeconds: 600
  - id: worker
    paths: ["apps/worker/**"]
    exec: ["make", "-C", "apps/worker", "install"]
    timeoutSeconds: 1800
items:
  - id: markdown
    kind: command
    gate: beforePR
    exec: ["make", "check-markdown"]
    timeoutSeconds: 120
"#,
        )
        .unwrap();
        let policy = match load_policy(root) {
            LoadResult::Ready(policy) => policy,
            LoadResult::Failed { message, .. } => panic!("{message}"),
        };
        assert_eq!(policy.setup.len(), 2);
        assert_eq!(policy.setup[0].id, "js");
        assert_eq!(policy.setup[0].kind_name(), "setup");
        assert!(policy.setup[0].paths.is_empty());
        assert_eq!(policy.setup[1].paths, ["apps/worker/**"]);
        let body: Value = serde_json::from_str(&canonical_policy_body(&policy).unwrap()).unwrap();
        assert_eq!(body["setup"][0]["kind"], "setup");
        assert_eq!(body["setup"][0]["gate"], "beforePR");
        assert_eq!(body["setup"][0]["exec"], json!(["bun", "install"]));
        assert_eq!(body["setup"][0]["timeoutSeconds"], json!(600));
        assert!(body["setup"][0].get("paths").is_none());
        assert_eq!(body["setup"][1]["paths"], json!(["apps/worker/**"]));
        assert_eq!(body["setup"][1]["id"], "worker");

        fs::write(root.join(".agents/closeout.yaml"), "specVersion: \"0.1\"\nsetup: []\n").unwrap();
        match load_policy(root) {
            LoadResult::Failed { message, .. } => assert!(message.contains("setup"), "{message}"),
            LoadResult::Ready(_) => panic!("empty setup should fail"),
        }

        fs::write(
            root.join(".agents/closeout.yaml"),
            "specVersion: \"0.1\"\nsetup:\n  - id: markdown\n    exec: [\"true\"]\n    timeoutSeconds: 30\nitems:\n  - id: markdown\n    kind: command\n    gate: beforePR\n    exec: [\"true\"]\n    timeoutSeconds: 30\n",
        )
        .unwrap();
        match load_policy(root) {
            LoadResult::Failed { message, .. } => assert!(message.contains("duplicate requirement id markdown"), "{message}"),
            LoadResult::Ready(_) => panic!("duplicate id should fail"),
        }

        fs::write(
            root.join(".agents/closeout/extra.yaml"),
            "specVersion: \"0.1\"\nsetup:\n  - id: js\n    exec: [\"true\"]\n    timeoutSeconds: 30\n",
        )
        .unwrap();
        fs::write(
            root.join(".agents/closeout.yaml"),
            "specVersion: \"0.1\"\nimports:\n  - path: .agents/closeout/extra.yaml\n    as: extra\n",
        )
        .unwrap();
        match load_policy(root) {
            LoadResult::Failed { message, .. } => assert_eq!(message, "setup is only allowed on the entry policy"),
            LoadResult::Ready(_) => panic!("imported setup should fail"),
        }
    }
}
