use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

pub fn canonical_json(value: &Value) -> Result<String, String> {
    canonicalize(value)
}

pub fn digest_of(value: &Value) -> Result<String, String> {
    Ok(format!("sha256:{}", sha256_hex(canonical_json(value)?.as_bytes())))
}

pub fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn canonicalize(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(true) => Ok("true".to_string()),
        Value::Bool(false) => Ok("false".to_string()),
        Value::String(text) => serde_json::to_string(text).map_err(|err| err.to_string()),
        Value::Number(number) => canonical_number(number),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(canonicalize(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| utf16_cmp(left, right));
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let encoded = serde_json::to_string(key).map_err(|err| err.to_string())?;
                let child = canonicalize(&map[key])?;
                parts.push(format!("{encoded}:{child}"));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

fn canonical_number(number: &serde_json::Number) -> Result<String, String> {
    const MAX: i64 = 9_007_199_254_740_991;
    if let Some(value) = number.as_i64() {
        if (-MAX..=MAX).contains(&value) {
            return Ok(value.to_string());
        }
    } else if let Some(value) = number.as_u64() {
        if value <= MAX as u64 {
            return Ok(value.to_string());
        }
    }
    Err("canonical JSON only accepts safe integers".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_and_keeps_array_order() {
        let value = json!({"b": [2, 1], "a": {"d": true, "c": "x/y"}});
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":{"c":"x/y","d":true},"b":[2,1]}"#);
    }

    #[test]
    fn rejects_non_integers() {
        let value = json!(1.5);
        assert!(canonical_json(&value).unwrap_err().contains("safe integers"));
    }

    #[test]
    fn sorts_by_utf16_code_units() {
        let value = json!({"\u{1F600}": 1, "a": 2, "\u{E000}": 3});
        let text = canonical_json(&value).unwrap();
        let ascii = text.find("\"a\"").unwrap();
        let emoji = text.find("\"\u{1F600}\"").unwrap();
        let private = text.find("\"\u{E000}\"").unwrap();
        assert!(ascii < emoji && emoji < private, "{text}");
    }
}
