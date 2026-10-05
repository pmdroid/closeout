use crate::paths::check_path_patterns;
use crate::schema::check_legacy;
use crate::types::{Independence, Item, Severity, Warning, LEGACY_COMMAND_TIMEOUT_SECONDS};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct LegacyDocument {
    items: Vec<LegacyItem>,
}

#[derive(Deserialize)]
struct LegacyItem {
    id: String,
    kind: String,
    run: Option<String>,
    hint: Option<String>,
    skill: Option<String>,
    providers: Option<Vec<String>>,
    #[serde(rename = "differentProvider")]
    different_provider: Option<bool>,
    #[serde(rename = "failOn")]
    fail_on: Option<Severity>,
    #[serde(rename = "timeoutSeconds")]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    paths: Vec<String>,
}

pub fn map_legacy(document: &Value) -> Result<(Vec<Item>, Vec<Warning>), String> {
    check_legacy(document)?;
    let retry = document.get("retry").is_some();
    let body: LegacyDocument = serde_json::from_value(document.clone()).map_err(|err| err.to_string())?;
    let mut warnings = vec![Warning {
        code: "legacy-path".to_string(),
        message: "Reading legacy policy .acpdash/closeout.yaml. The public entry is .agents/closeout.yaml.".to_string(),
    }];
    if retry {
        warnings.push(Warning {
            code: "legacy-retry".to_string(),
            message: "Ignored retry. Retry scheduling is outside the acceptance decision.".to_string(),
        });
    }
    let mut hinted = Vec::new();
    let mut provided = Vec::new();
    let mut shelled = Vec::new();
    let mut timed = Vec::new();
    let mut items = Vec::new();
    for item in body.items {
        let paths = check_path_patterns(&item.paths)?;
        if item.hint.is_some() {
            hinted.push(item.id.clone());
        }
        if item.kind == "command" {
            let Some(run) = item.run else {
                return Err(format!("command {} is missing run", item.id));
            };
            if item.skill.is_some() || item.providers.is_some() || item.different_provider == Some(true) || item.fail_on.is_some() {
                return Err(format!("command {} has review fields", item.id));
            }
            shelled.push(item.id.clone());
            let timeout_seconds = item.timeout_seconds.unwrap_or(LEGACY_COMMAND_TIMEOUT_SECONDS);
            if item.timeout_seconds.is_none() {
                timed.push(item.id.clone());
            }
            let mut built = Item::command(item.id, vec!["sh".to_string(), "-c".to_string(), run], timeout_seconds);
            built.paths = paths;
            items.push(built);
            continue;
        }
        if item.kind == "review" {
            let Some(skill) = item.skill else {
                return Err(format!("review {} is missing skill", item.id));
            };
            let Some(fail_on) = item.fail_on else {
                return Err(format!("review {} is missing failOn", item.id));
            };
            if item.run.is_some() {
                return Err(format!("review {} has a run field", item.id));
            }
            if item.providers.as_ref().is_some_and(|providers| !providers.is_empty()) {
                provided.push(item.id.clone());
            }
            let mut built = Item::review(
                item.id,
                skill,
                Independence {
                    different_session: false,
                    different_model: false,
                    different_provider: item.different_provider == Some(true),
                },
                fail_on,
            );
            built.paths = paths;
            items.push(built);
            continue;
        }
        if item.run.is_some()
            || item.skill.is_some()
            || item.providers.is_some()
            || item.different_provider == Some(true)
            || item.fail_on.is_some()
            || item.timeout_seconds.is_some()
        {
            return Err(format!("{} {} mixes fields the kind does not use", item.kind, item.id));
        }
        let mut built = Item::unsupported(item.id, item.kind);
        built.paths = paths;
        items.push(built);
    }
    if !hinted.is_empty() {
        warnings.push(Warning {
            code: "legacy-hint".to_string(),
            message: format!("Ignored hint on {}.", hinted.join(", ")),
        });
    }
    if !provided.is_empty() {
        warnings.push(Warning {
            code: "legacy-providers".to_string(),
            message: format!(
                "Ignored providers on {}. Provider lists are outside the acceptance document.",
                provided.join(", ")
            ),
        });
    }
    if !shelled.is_empty() {
        warnings.push(Warning {
            code: "legacy-shell".to_string(),
            message: format!("Command {} uses a shell string.", shelled.join(", ")),
        });
    }
    if !timed.is_empty() {
        warnings.push(Warning {
            code: "legacy-timeout".to_string(),
            message: format!(
                "Command {} has no timeoutSeconds. Using {LEGACY_COMMAND_TIMEOUT_SECONDS}.",
                timed.join(", ")
            ),
        });
    }
    Ok((items, warnings))
}
