use crate::canonical::canonical_json;
use crate::schema::check_decision;
use crate::types::{Decision, DecisionName};
use serde_json::Value;

pub fn format_decision(decision: &Decision) -> String {
    let mut lines = vec![
        format!("{} {}", decision.decision.as_str(), decision.gate.as_str()),
        format!("base {}", dash(&decision.base)),
        format!("head {}", dash(&decision.head)),
        format!("policy {}", decision.policy.digest.as_deref().unwrap_or("none")),
    ];
    if let Some(message) = &decision.message {
        lines.push(message.clone());
    }
    if !decision.items.is_empty() {
        lines.push(String::new());
    }
    for item in &decision.items {
        lines.push(format!("{}  {}  {}", item.id, item.state.as_str(), item.message));
    }
    format!("{}\n", lines.join("\n"))
}

pub fn exit_status(decision: &Decision) -> i32 {
    match decision.decision {
        DecisionName::Accepted => 0,
        DecisionName::Rejected => 1,
        DecisionName::Blocked => 3,
    }
}

fn dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

pub fn format_markdown(decision: &Decision) -> Result<String, String> {
    let value = serde_json::to_value(decision).map_err(|err| err.to_string())?;
    let json = canonical_json(&value)?;
    let mut lines = vec![
        format!("# Closeout {}", decision.gate.as_str()),
        String::new(),
        format!("decision: {}", decision.decision.as_str()),
        format!("base: {}", dash(&decision.base)),
        format!("head: {}", dash(&decision.head)),
        format!("policy: {}", decision.policy.digest.as_deref().unwrap_or("none")),
    ];
    if let Some(message) = &decision.message {
        lines.push(format!("note: {}", flatten(message)));
    }
    for warning in &decision.warnings {
        lines.push(format!("warning: {} {}", warning.code, flatten(&warning.message)));
    }
    if !decision.items.is_empty() {
        lines.push(String::new());
        lines.push("| Requirement | State | Record |".to_string());
        lines.push("| --- | --- | --- |".to_string());
        for item in &decision.items {
            lines.push(format!("| {} | {} | {} |", cell(&item.id), item.state.as_str(), cell(&item.message)));
        }
    }
    lines.push(String::new());
    lines.push("```json".to_string());
    lines.push(json);
    lines.push("```".to_string());
    Ok(format!("{}\n", lines.join("\n")))
}

pub fn decision_from_markdown(body: &str) -> Result<Decision, String> {
    let marker = "\n```json\n";
    let start = body.rfind(marker).ok_or("sealed report is missing the decision")?;
    let rest = &body[start + marker.len()..];
    let end = rest.find("\n```").ok_or("sealed report is missing the decision")?;
    let value: Value = serde_json::from_str(&rest[..end]).map_err(|_| "sealed report decision is invalid".to_string())?;
    check_decision(&value)?;
    let decision: Decision = serde_json::from_value(value).map_err(|err| err.to_string())?;
    if format_markdown(&decision)? != body {
        return Err("sealed report does not match the decision".to_string());
    }
    Ok(decision)
}

fn flatten(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn cell(value: &str) -> String {
    flatten(value).replace('|', "/")
}
