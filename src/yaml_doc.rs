use serde_json::Value;
use saphyr_parser::{Event, Parser};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn read_yaml_file(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|_| "could not read the policy file".to_string())?;
    read_yaml_value(&text)
}

pub fn read_yaml_value(text: &str) -> Result<Value, String> {
    ensure_unique_keys(text)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(text).map_err(|err| err.to_string())?;
    serde_json::to_value(yaml).map_err(|err| err.to_string())
}

fn ensure_unique_keys(text: &str) -> Result<(), String> {
    let mut stack: Vec<Frame> = Vec::new();
    for event in Parser::new_from_str(text) {
        let (event, _) = event.map_err(|err| {
            let info = err.info();
            if info.is_empty() { "invalid YAML".to_string() } else { info.to_string() }
        })?;
        match event {
            Event::Scalar(value, _, _, _) => {
                if let Some(Frame::Map { keys, expect_key }) = stack.last_mut() {
                    if *expect_key {
                        if !keys.insert(value.into_owned()) {
                            return Err("duplicated mapping key".to_string());
                        }
                        *expect_key = false;
                        continue;
                    }
                }
                accept_value(&mut stack)?;
            }
            Event::MappingStart(_, _) => {
                accept_value(&mut stack)?;
                stack.push(Frame::Map {
                    keys: HashSet::new(),
                    expect_key: true,
                });
            }
            Event::SequenceStart(_, _) => {
                accept_value(&mut stack)?;
                stack.push(Frame::Seq);
            }
            Event::MappingEnd | Event::SequenceEnd => {
                if stack.pop().is_none() {
                    return Err("invalid YAML".to_string());
                }
            }
            Event::Alias(_) => {
                if let Some(Frame::Map { expect_key: true, .. }) = stack.last() {
                    return Err("invalid YAML".to_string());
                }
                accept_value(&mut stack)?;
            }
            Event::StreamStart | Event::StreamEnd | Event::DocumentStart(_) | Event::DocumentEnd | Event::Nothing => {}
        }
    }
    Ok(())
}

fn accept_value(stack: &mut [Frame]) -> Result<(), String> {
    let Some(frame) = stack.last_mut() else {
        return Ok(());
    };
    match frame {
        Frame::Map { expect_key, .. } => {
            if *expect_key {
                return Err("invalid YAML".to_string());
            }
            *expect_key = true;
            Ok(())
        }
        Frame::Seq => Ok(()),
    }
}

enum Frame {
    Map { keys: HashSet<String>, expect_key: bool },
    Seq,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_duplicated_mapping_key() {
        let err = read_yaml_value("specVersion: \"0.1\"\nspecVersion: \"0.1\"\n").unwrap_err();
        assert!(err.contains("duplicated mapping key"), "{err}");
    }

    #[test]
    fn rejects_a_nested_duplicate() {
        let text = "items:\n  - id: check\n    id: check\n";
        let err = read_yaml_value(text).unwrap_err();
        assert!(err.contains("duplicated mapping key"), "{err}");
    }

    #[test]
    fn reads_a_policy_document() {
        let value = read_yaml_value("specVersion: \"0.1\"\nitems: []\n").unwrap();
        assert_eq!(value["specVersion"], "0.1");
        assert!(value["items"].as_array().unwrap().is_empty());
    }
}
