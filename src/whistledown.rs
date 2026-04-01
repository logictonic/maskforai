//! Whistledown: reversible, consistent PII masking.
//!
//! Replaces PII values with numbered tokens (e.g. `[[EMAIL_1]]`, `[[PHONE_2]]`)
//! and maintains a bidirectional map to restore originals in LLM responses.

use crate::config::PatternsConfig;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

struct BuiltinPattern {
    pattern: &'static str,
    entity_type: &'static str,
}

const WHISTLEDOWN_PATTERNS: &[BuiltinPattern] = &[
    BuiltinPattern { pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", entity_type: "EMAIL" },
    BuiltinPattern { pattern: r"\+?[0-9]{10,15}", entity_type: "PHONE" },
    BuiltinPattern { pattern: r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", entity_type: "SSN" },
    BuiltinPattern { pattern: r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", entity_type: "IP" },
    BuiltinPattern { pattern: r"(?i)itneuro", entity_type: "BRAND" },
    BuiltinPattern { pattern: r"(?i)lifely", entity_type: "BRAND" },
];

/// Compiled built-in + custom Whistledown regexes (from `patterns.toml`).
pub struct WhistledownPatternSet {
    set: RegexSet,
    regexes: Vec<Regex>,
    entity_types: Vec<String>,
}

impl WhistledownPatternSet {
    /// Built-in patterns only (for unit tests).
    pub fn builtins_only() -> Self {
        let mut pattern_strs = Vec::new();
        let mut regexes = Vec::new();
        let mut entity_types = Vec::new();
        for b in WHISTLEDOWN_PATTERNS {
            pattern_strs.push(b.pattern.to_string());
            regexes.push(Regex::new(b.pattern).expect("builtin whistledown regex"));
            entity_types.push(b.entity_type.to_string());
        }
        let set =
            RegexSet::new(&pattern_strs.iter().map(|s| s.as_str()).collect::<Vec<_>>()).unwrap();
        Self {
            set,
            regexes,
            entity_types,
        }
    }

    /// Merge builtins with `[[whistledown_pattern]]` entries; invalid custom regexes are logged and skipped.
    pub fn compile_from_patterns_config(config: &PatternsConfig) -> Self {
        let mut pattern_strs: Vec<String> = Vec::new();
        let mut regexes: Vec<Regex> = Vec::new();
        let mut entity_types: Vec<String> = Vec::new();

        for b in WHISTLEDOWN_PATTERNS {
            pattern_strs.push(b.pattern.to_string());
            regexes.push(Regex::new(b.pattern).expect("builtin whistledown regex"));
            entity_types.push(b.entity_type.to_string());
        }

        for w in &config.whistledown_pattern {
            match Regex::new(&w.regex) {
                Ok(re) => {
                    pattern_strs.push(w.regex.clone());
                    regexes.push(re);
                    entity_types.push(w.entity_type.clone());
                }
                Err(e) => tracing::warn!(
                    pattern = %w.regex,
                    entity_type = %w.entity_type,
                    error = %e,
                    "Skipping invalid Whistledown regex"
                ),
            }
        }

        let set = RegexSet::new(&pattern_strs.iter().map(|s| s.as_str()).collect::<Vec<_>>())
            .expect("whistledown RegexSet");
        Self {
            set,
            regexes,
            entity_types,
        }
    }
}

impl Default for WhistledownPatternSet {
    fn default() -> Self {
        Self::builtins_only()
    }
}

/// Same opaque-field rules as `mask::mask_responses_value_full` / `is_opaque_responses_field`.
fn is_opaque_responses_field(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("encrypted") || matches!(key.as_str(), "ciphertext" | "auth_tag" | "tag" | "iv")
}

/// Bidirectional map for whistledown replacement/restoration.
pub struct WhistledownMap {
    patterns: Arc<WhistledownPatternSet>,
    allowlist: Vec<String>,
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
    counters: HashMap<String, u32>,
}

impl WhistledownMap {
    pub fn new(patterns: Arc<WhistledownPatternSet>, allowlist: Vec<String>) -> Self {
        Self {
            patterns,
            allowlist,
            forward: HashMap::new(),
            reverse: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    /// Unit tests: built-in patterns, empty allowlist.
    pub fn test_builtins() -> Self {
        Self::new(Arc::new(WhistledownPatternSet::builtins_only()), Vec::new())
    }

    fn get_or_create_token(&mut self, value: &str, entity_type: &str) -> String {
        if let Some(token) = self.forward.get(value) {
            return token.clone();
        }
        let counter = self.counters.entry(entity_type.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[[{}_{}]]", entity_type, counter);
        self.forward.insert(value.to_string(), token.clone());
        self.reverse.insert(token.clone(), value.to_string());
        token
    }

    /// Apply whistledown to Messages-style JSON (system + messages[].content).
    pub fn apply(&mut self, body: &mut Value) {
        if let Some(obj) = body.as_object_mut() {
            if let Some(system) = obj.get_mut("system") {
                self.apply_value(system);
            }
            if let Some(messages) = obj.get_mut("messages") {
                if let Some(arr) = messages.as_array_mut() {
                    for msg in arr.iter_mut() {
                        self.apply_message(msg);
                    }
                }
            }
        }
    }

    /// Apply whistledown to OpenAI Responses API body (`instructions`, `input`).
    pub fn apply_responses(&mut self, body: &mut Value) {
        if let Some(obj) = body.as_object_mut() {
            if let Some(instructions) = obj.get_mut("instructions") {
                self.apply_value(instructions);
            }
            if let Some(input) = obj.get_mut("input") {
                self.apply_responses_value(input);
            }
        }
    }

    fn apply_message(&mut self, msg: &mut Value) {
        if let Some(obj) = msg.as_object_mut() {
            if let Some(content) = obj.get_mut("content") {
                self.apply_content(content);
            }
        }
    }

    fn apply_content(&mut self, content: &mut Value) {
        match content {
            Value::String(s) => {
                *s = self.replace_in_text(s);
            }
            Value::Array(arr) => {
                for block in arr.iter_mut() {
                    if let Some(obj) = block.as_object_mut() {
                        if obj.get("type").and_then(|v| v.as_str()) == Some("text") {
                            if let Some(text) = obj.get_mut("text") {
                                if let Some(s) = text.as_str() {
                                    let replaced = self.replace_in_text(s);
                                    *text = Value::String(replaced);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_value(&mut self, v: &mut Value) {
        match v {
            Value::String(s) => {
                *s = self.replace_in_text(s);
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.apply_value(item);
                }
            }
            Value::Object(obj) => {
                for (_, val) in obj.iter_mut() {
                    self.apply_value(val);
                }
            }
            _ => {}
        }
    }

    fn apply_responses_value(&mut self, v: &mut Value) {
        match v {
            Value::String(s) => {
                *s = self.replace_in_text(s);
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.apply_responses_value(item);
                }
            }
            Value::Object(obj) => {
                for (key, val) in obj.iter_mut() {
                    if is_opaque_responses_field(key) {
                        continue;
                    }
                    self.apply_responses_value(val);
                }
            }
            _ => {}
        }
    }

    fn allowlist_skip(&self, matched: &str) -> bool {
        self.allowlist.iter().any(|a| a == matched)
    }

    fn replace_in_text(&mut self, text: &str) -> String {
        let set_matches = self.patterns.set.matches(text);
        if !set_matches.matched_any() {
            return text.to_string();
        }

        let mut all_matches: Vec<(usize, usize, String)> = Vec::new();

        for idx in set_matches.iter() {
            let re = &self.patterns.regexes[idx];
            let entity_type = &self.patterns.entity_types[idx];
            for m in re.find_iter(text) {
                let fragment = &text[m.start()..m.end()];
                if self.allowlist_skip(fragment) {
                    continue;
                }
                all_matches.push((m.start(), m.end(), entity_type.clone()));
            }
        }

        all_matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

        let mut filtered: Vec<(usize, usize, String)> = Vec::new();
        for m in all_matches {
            if let Some(last) = filtered.last() {
                if m.0 < last.1 {
                    continue;
                }
            }
            filtered.push(m);
        }

        let mut result = text.to_string();
        for (start, end, entity_type) in filtered.into_iter().rev() {
            let original = &text[start..end];
            let token = self.get_or_create_token(original, &entity_type);
            result.replace_range(start..end, &token);
        }

        result
    }

    /// Restore original values in a response string.
    pub fn restore(&self, text: &str) -> String {
        if self.reverse.is_empty() {
            return text.to_string();
        }
        let mut result = text.to_string();
        for (token, original) in &self.reverse {
            result = result.replace(token, original);
        }
        result
    }

    pub fn has_mappings(&self) -> bool {
        !self.forward.is_empty()
    }

    pub fn mappings_count(&self) -> usize {
        self.forward.len()
    }

    pub fn summary(&self) -> String {
        let mut type_counts: HashMap<&str, u32> = HashMap::new();
        for token in self.reverse.keys() {
            if let Some(inner) = token.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
                if let Some(idx) = inner.rfind('_') {
                    let etype = &inner[..idx];
                    *type_counts.entry(etype).or_insert(0) += 1;
                }
            }
        }
        let mut parts: Vec<String> = type_counts.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        parts.sort();
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WhistledownPatternDef;

    #[test]
    fn whistledown_replaces_email() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Contact user@example.com for help");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(!result.contains("user@example.com"), "got: {}", result);
    }

    #[test]
    fn whistledown_consistent_tokens() {
        let mut map = WhistledownMap::test_builtins();
        let r1 = map.replace_in_text("Email: user@example.com");
        let r2 = map.replace_in_text("Also user@example.com");
        assert!(r1.contains("[[EMAIL_1]]"));
        assert!(r2.contains("[[EMAIL_1]]"));
    }

    #[test]
    fn whistledown_different_values_different_tokens() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Email a@b.com and c@d.com");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(result.contains("[[EMAIL_2]]"), "got: {}", result);
    }

    #[test]
    fn whistledown_restore() {
        let mut map = WhistledownMap::test_builtins();
        let masked = map.replace_in_text("Contact user@example.com please");
        assert!(masked.contains("[[EMAIL_1]]"));
        let restored = map.restore(&masked);
        assert!(restored.contains("user@example.com"), "got: {}", restored);
        assert!(!restored.contains("[[EMAIL_1]]"), "got: {}", restored);
    }

    #[test]
    fn whistledown_phone() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Call +79991234567");
        assert!(result.contains("[[PHONE_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("+79991234567"));
    }

    #[test]
    fn whistledown_multiple_types() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Email user@test.com, phone +11234567890");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(result.contains("[[PHONE_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("user@test.com"));
        assert!(restored.contains("+11234567890"));
    }

    #[test]
    fn whistledown_json_body() {
        let mut map = WhistledownMap::test_builtins();
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Email me at admin@corp.com"}
            ]
        });
        map.apply(&mut body);
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[[EMAIL_1]]"), "got: {}", content);
        assert!(!content.contains("admin@corp.com"), "got: {}", content);
    }

    #[test]
    fn whistledown_no_pii_unchanged() {
        let mut map = WhistledownMap::test_builtins();
        let s = "Hello world, nothing sensitive here";
        let result = map.replace_in_text(s);
        assert_eq!(result, s);
    }

    #[test]
    fn whistledown_ip_address() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Server at 192.168.1.100");
        assert!(result.contains("[[IP_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("192.168.1.100"));
    }

    #[test]
    fn whistledown_ssn() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("SSN is 123-45-6789");
        assert!(result.contains("[[SSN_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("123-45-6789"));
    }

    #[test]
    fn whistledown_brand_lifely_standalone() {
        let mut map = WhistledownMap::test_builtins();
        let result = map.replace_in_text("Проект Lifely от itneuro");
        assert!(result.contains("[[BRAND_1]]"), "got: {}", result);
        assert!(result.contains("[[BRAND_2]]"), "got: {}", result);
        assert!(!result.contains("Lifely"), "got: {}", result);
        assert!(!result.contains("itneuro"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("Lifely"));
        assert!(restored.contains("itneuro"));
    }

    #[test]
    fn whistledown_brand_in_identifiers() {
        let mut map = WhistledownMap::test_builtins();
        let r1 = map.replace_in_text("class LifelyPlatform extends Base");
        assert!(r1.contains("Platform"), "got: {}", r1);
        assert!(r1.contains("[[BRAND_"), "got: {}", r1);
        assert!(!r1.contains("Lifely"), "got: {}", r1);
        let r2 = map.replace_in_text("from lifely_utils import helper");
        assert!(r2.contains("_utils"), "got: {}", r2);
        assert!(r2.contains("[[BRAND_"), "got: {}", r2);
        assert!(!r2.contains("lifely"), "got: {}", r2);
        let r3 = map.replace_in_text("com.lifely.app.services");
        assert!(r3.contains("com."), "got: {}", r3);
        assert!(r3.contains(".app"), "got: {}", r3);
        assert!(r3.contains("[[BRAND_"), "got: {}", r3);
        let r4 = map.replace_in_text("ItneuroPlatform API");
        assert!(r4.contains("Platform"), "got: {}", r4);
        assert!(r4.contains("[[BRAND_"), "got: {}", r4);
        assert!(!r4.contains("Itneuro"), "got: {}", r4);
    }

    #[test]
    fn whistledown_brand_restore_roundtrip() {
        let mut map = WhistledownMap::test_builtins();
        let original = "from lifely_platform import LifelyMentor; // itneuro backend";
        let masked = map.replace_in_text(original);
        assert!(!masked.contains("lifely"));
        assert!(!masked.contains("Lifely"));
        assert!(!masked.contains("itneuro"));
        let restored = map.restore(&masked);
        assert_eq!(restored, original, "roundtrip failed");
    }

    #[test]
    fn whistledown_custom_pattern_from_config() {
        let cfg = PatternsConfig {
            whistledown_pattern: vec![WhistledownPatternDef {
                regex: r"sk-\d{4}TEST".to_string(),
                entity_type: "TESTKEY".to_string(),
            }],
            ..Default::default()
        };
        let set = WhistledownPatternSet::compile_from_patterns_config(&cfg);
        let mut map = WhistledownMap::new(Arc::new(set), vec![]);
        let result = map.replace_in_text("token sk-1234TEST end");
        assert!(result.contains("[[TESTKEY_1]]"), "got: {}", result);
        assert!(!result.contains("sk-1234TEST"), "got: {}", result);
    }

    #[test]
    fn whistledown_allowlist_skips_match() {
        let mut map = WhistledownMap::new(
            Arc::new(WhistledownPatternSet::builtins_only()),
            vec!["user@allow.list".to_string()],
        );
        let result = map.replace_in_text("Email user@allow.list and other@x.com");
        assert!(result.contains("user@allow.list"), "got: {}", result);
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(!result.contains("other@x.com"));
    }

    #[test]
    fn whistledown_apply_responses_skips_encrypted_field() {
        let set = WhistledownPatternSet::builtins_only();
        let mut map = WhistledownMap::new(Arc::new(set), vec![]);
        let secret = "enc-pass@corp.com";
        let mut body = serde_json::json!({
            "model": "gpt-5",
            "instructions": "Reach admin@corp.com",
            "input": [{
                "role": "user",
                "content": "Hello",
                "encrypted_content": secret
            }]
        });
        map.apply_responses(&mut body);
        let instr = body["instructions"].as_str().unwrap();
        assert!(
            instr.contains("[[EMAIL_1]]"),
            "instructions should mask email: {}",
            instr
        );
        let enc = body["input"][0]["encrypted_content"].as_str().unwrap();
        assert_eq!(enc, secret, "opaque field must stay intact");
    }

    #[test]
    fn whistledown_apply_responses_string_input() {
        let mut map = WhistledownMap::test_builtins();
        let mut body = serde_json::json!({
            "instructions": "sys",
            "input": "Mail to user@responses.api"
        });
        map.apply_responses(&mut body);
        let input = body["input"].as_str().unwrap();
        assert!(input.contains("[[EMAIL_1]]"), "got: {}", input);
    }
}
