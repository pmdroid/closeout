use jsonschema::Validator;
use serde_json::Value;
use std::sync::OnceLock;

pub fn check_policy(value: &Value) -> Result<(), String> {
    check(policy_validator(), value)
}

pub fn check_evidence(value: &Value) -> Result<(), String> {
    check(evidence_validator(), value)
}

pub fn check_decision(value: &Value) -> Result<(), String> {
    check(decision_validator(), value)
}

fn check(validator: &Validator, value: &Value) -> Result<(), String> {
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(schema_errors(validator, value))
    }
}

fn schema_errors(validator: &Validator, instance: &Value) -> String {
    let Some(error) = validator.iter_errors(instance).next() else {
        return "document does not match the schema".to_string();
    };
    let path = error.instance_path().as_str();
    let path = if path.is_empty() { "/" } else { path };
    format!("{path} {error}")
}

fn policy_validator() -> &'static Validator {
    static CELL: OnceLock<Validator> = OnceLock::new();
    CELL.get_or_init(|| compile(include_str!("../schema/policy.schema.json")))
}

fn evidence_validator() -> &'static Validator {
    static CELL: OnceLock<Validator> = OnceLock::new();
    CELL.get_or_init(|| compile(include_str!("../schema/evidence.schema.json")))
}

fn decision_validator() -> &'static Validator {
    static CELL: OnceLock<Validator> = OnceLock::new();
    CELL.get_or_init(|| compile(include_str!("../schema/decision.schema.json")))
}

fn compile(text: &str) -> Validator {
    let schema: Value = serde_json::from_str(text).expect("bundled schema is JSON");
    jsonschema::draft202012::options()
        .build(&schema)
        .expect("bundled schema compiles")
}
