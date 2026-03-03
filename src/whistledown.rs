//! Whistledown: reversible, consistent PII masking.
//!
//! Replaces PII values with numbered tokens (e.g. `[[EMAIL_1]]`, `[[PHONE_2]]`)
//! and maintains a bidirectional map to restore originals in LLM responses.

use regex::{Regex, RegexSet};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Whistledown entity type and its regex.
struct WhistledownPattern {
    pattern: &'static str,
    entity_type: &'static str,
}

const WHISTLEDOWN_PATTERNS: &[WhistledownPattern] = &[
    WhistledownPattern { pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", entity_type: "EMAIL" },
    WhistledownPattern { pattern: r"\+?[0-9]{10,15}", entity_type: "PHONE" },
    WhistledownPattern { pattern: r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", entity_type: "SSN" },
    WhistledownPattern { pattern: r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", entity_type: "IP" },
];

fn whistledown_regexes() -> &'static [(Regex, &'static str)] {
    static REGEXES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        WHISTLEDOWN_PATTERNS
            .iter()
            .map(|wp| (Regex::new(wp.pattern).unwrap(), wp.entity_type))
            .collect()
    })
}

fn whistledown_regex_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        let patterns: Vec<&str> = WHISTLEDOWN_PATTERNS.iter().map(|wp| wp.pattern).collect();
        RegexSet::new(&patterns).unwrap()
    })
}

/// Bidirectional map for whistledown replacement/restoration.
pub struct WhistledownMap {
    /// original value -> token (e.g. "user@test.com" -> "[[EMAIL_1]]")
    forward: HashMap<String, String>,
    /// token -> original value (e.g. "[[EMAIL_1]]" -> "user@test.com")
    reverse: HashMap<String, String>,
    /// Counter per entity type
    counters: HashMap<String, u32>,
}

impl WhistledownMap {
    pub fn new() -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    /// Get or create a token for a value.
    fn get_or_create_token(&mut self, value: &str, entity_type: &str) -> String {
        if let Some(token) = self.forward.get(value) {
            return token.clone();
        }
        let counter = self.counters.entry(entity_type.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[[{}_{:}]]", entity_type, counter);
        self.forward.insert(value.to_string(), token.clone());
        self.reverse.insert(token.clone(), value.to_string());
        token
    }

    /// Apply whistledown to a JSON body (mutate in place).
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

    /// Replace PII in text with whistledown tokens.
    fn replace_in_text(&mut self, text: &str) -> String {
        let set_matches = whistledown_regex_set().matches(text);
        if !set_matches.matched_any() {
            return text.to_string();
        }

        let regexes = whistledown_regexes();
        // Collect all matches with positions
        let mut all_matches: Vec<(usize, usize, String)> = Vec::new();

        for idx in set_matches.iter() {
            let (re, entity_type) = &regexes[idx];
            for m in re.find_iter(text) {
                all_matches.push((m.start(), m.end(), entity_type.to_string()));
            }
        }

        // Sort by position (start ascending, longer match first for same start)
        all_matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

        // Remove overlapping matches (keep first/longest)
        let mut filtered: Vec<(usize, usize, String)> = Vec::new();
        for m in all_matches {
            if let Some(last) = filtered.last() {
                if m.0 < last.1 {
                    continue; // overlaps with previous
                }
            }
            filtered.push(m);
        }

        // Apply replacements in reverse order to preserve positions
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

    /// Returns true if any mappings exist.
    pub fn has_mappings(&self) -> bool {
        !self.forward.is_empty()
    }

    /// Returns the number of unique PII values mapped.
    pub fn mappings_count(&self) -> usize {
        self.forward.len()
    }

    /// Returns a summary of mappings for logging (type counts).
    pub fn summary(&self) -> String {
        let mut type_counts: HashMap<&str, u32> = HashMap::new();
        for token in self.reverse.keys() {
            // Token format: [[TYPE_N]]
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

    #[test]
    fn whistledown_replaces_email() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("Contact user@example.com for help");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(!result.contains("user@example.com"), "got: {}", result);
    }

    #[test]
    fn whistledown_consistent_tokens() {
        let mut map = WhistledownMap::new();
        let r1 = map.replace_in_text("Email: user@example.com");
        let r2 = map.replace_in_text("Also user@example.com");
        // Same value should get same token
        assert!(r1.contains("[[EMAIL_1]]"));
        assert!(r2.contains("[[EMAIL_1]]"));
    }

    #[test]
    fn whistledown_different_values_different_tokens() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("Email a@b.com and c@d.com");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(result.contains("[[EMAIL_2]]"), "got: {}", result);
    }

    #[test]
    fn whistledown_restore() {
        let mut map = WhistledownMap::new();
        let masked = map.replace_in_text("Contact user@example.com please");
        assert!(masked.contains("[[EMAIL_1]]"));
        let restored = map.restore(&masked);
        assert!(restored.contains("user@example.com"), "got: {}", restored);
        assert!(!restored.contains("[[EMAIL_1]]"), "got: {}", restored);
    }

    #[test]
    fn whistledown_phone() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("Call +79991234567");
        assert!(result.contains("[[PHONE_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("+79991234567"));
    }

    #[test]
    fn whistledown_multiple_types() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("Email user@test.com, phone +11234567890");
        assert!(result.contains("[[EMAIL_1]]"), "got: {}", result);
        assert!(result.contains("[[PHONE_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("user@test.com"));
        assert!(restored.contains("+11234567890"));
    }

    #[test]
    fn whistledown_json_body() {
        let mut map = WhistledownMap::new();
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
        let mut map = WhistledownMap::new();
        let s = "Hello world, nothing sensitive here";
        let result = map.replace_in_text(s);
        assert_eq!(result, s);
    }

    #[test]
    fn whistledown_ip_address() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("Server at 192.168.1.100");
        assert!(result.contains("[[IP_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("192.168.1.100"));
    }

    #[test]
    fn whistledown_ssn() {
        let mut map = WhistledownMap::new();
        let result = map.replace_in_text("SSN is 123-45-6789");
        assert!(result.contains("[[SSN_1]]"), "got: {}", result);
        let restored = map.restore(&result);
        assert!(restored.contains("123-45-6789"));
    }
}
