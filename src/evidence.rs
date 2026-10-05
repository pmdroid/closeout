use crate::canonical::sha256_hex;
use crate::paths::to_posix;
use crate::schema::check_evidence;
use crate::types::{Decision, EvidenceRecord};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn read_evidence(dir: &Path) -> Result<Vec<EvidenceRecord>, String> {
    let folder = dir.join("evidence");
    let files = match walk_json(&folder) {
        Ok(files) => files,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("could not read the evidence directory".to_string()),
    };
    let mut records = Vec::new();
    for file in files {
        let rel = relative_posix(dir, &file);
        let text = fs::read_to_string(&file).map_err(|_| format!("evidence file {rel} is invalid"))?;
        let parsed: Value = serde_json::from_str(&text).map_err(|_| format!("evidence file {rel} is invalid"))?;
        if let Err(message) = check_evidence(&parsed) {
            return Err(format!("evidence file {rel} is invalid: {message}"));
        }
        let record = serde_json::from_value(parsed).map_err(|_| format!("evidence file {rel} is invalid"))?;
        records.push(record);
    }
    Ok(records)
}

pub fn next_attempt(records: &[EvidenceRecord], item_id: &str, base: &str, head: &str, digest: &str) -> u64 {
    records
        .iter()
        .filter(|record| record.item_id() == item_id && record.base() == base && record.head() == head && record.policy_digest() == digest)
        .map(|record| record.attempt())
        .max()
        .map_or(1, |attempt| attempt.saturating_add(1))
}

pub fn write_record(dir: &Path, record: &EvidenceRecord) -> Result<String, String> {
    let relative = evidence_path("evidence", record.policy_digest(), record.head(), record.item_id(), &format!("{}.json", record.attempt()))?;
    write_text(dir, &relative, &format!("{}\n", serde_json::to_string_pretty(record).map_err(|err| err.to_string())?))?;
    Ok(to_posix(&relative))
}

pub fn write_log(dir: &Path, digest: &str, head: &str, item_id: &str, attempt: u64, body: &str) -> Result<(String, String), String> {
    let relative = evidence_path("logs", digest, head, item_id, &format!("{attempt}.log"))?;
    write_text(dir, &relative, body)?;
    Ok((to_posix(&relative), sha256_hex(body.as_bytes())))
}

pub fn write_decision_file(dir: &Path, gate: &str, digest: &str, head: &str, body: &Decision) -> Result<(), String> {
    let hex = digest_hex(digest);
    let name = format!("{head}.json");
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err("decision path is invalid".to_string());
    }
    let mut relative = PathBuf::from("decisions");
    relative.push(gate);
    relative.push(hex);
    relative.push(name);
    let text = serde_json::to_string_pretty(body).map_err(|err| err.to_string())?;
    write_text(dir, &relative, &format!("{text}\n"))
}

fn evidence_path(root: &str, digest: &str, head: &str, item_id: &str, leaf: &str) -> Result<PathBuf, String> {
    if head.is_empty() || head.contains('/') || head.contains('\\') || head.contains('\0') {
        return Err("evidence path is invalid".to_string());
    }
    let mut relative = PathBuf::from(root);
    relative.push(digest_hex(digest));
    relative.push(head);
    for segment in item_id.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\') {
            return Err("evidence path is invalid".to_string());
        }
        relative.push(segment);
    }
    relative.push(leaf);
    Ok(relative)
}

fn write_text(dir: &Path, relative: &Path, body: &str) -> Result<(), String> {
    let absolute = dir.join(relative);
    if let Some(parent) = absolute.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::write(absolute, body).map_err(|err| err.to_string())
}

fn digest_hex(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

fn relative_posix(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map(to_posix).unwrap_or_else(|_| path.display().to_string())
}

fn walk_json(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let absolute = entry.path();
            let meta = fs::symlink_metadata(&absolute)?;
            if meta.file_type().is_symlink() {
                continue;
            } else if meta.is_dir() {
                stack.push(absolute);
            } else if meta.is_file() && absolute.extension().and_then(|ext| ext.to_str()) == Some("json") {
                found.push(absolute);
            }
        }
    }
    Ok(found)
}
