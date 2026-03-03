//! Masks sensitive data in Anthropic Messages API JSON payloads.

use crate::filter_log::FilterLogger;
use crate::patterns::{self, MaskResult};
use serde_json::Value;

/// Mask request body. Use `mask_request_body_full` for all options.
#[allow(dead_code)]
pub fn mask_request_body(body: &mut Value) -> Option<MaskResult> {
    mask_request_body_full(body, 0.0, &[], &mut None)
}

/// Mask request body with all options.
pub fn mask_request_body_full(
    body: &mut Value,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
) -> Option<MaskResult> {
    if let Some(obj) = body.as_object_mut() {
        if let Some(system) = obj.get_mut("system") {
            if let Some(block) = mask_value_full(system, min_score, allowlist, log, Some("system")) {
                return Some(block);
            }
        }
        if let Some(messages) = obj.get_mut("messages") {
            if let Some(arr) = messages.as_array_mut() {
                for (i, msg) in arr.iter_mut().enumerate() {
                    let ctx = format!("messages.{}", i);
                    if let Some(block) = mask_message_content_full(msg, min_score, allowlist, log, Some(&ctx)) {
                        return Some(block);
                    }
                }
            }
        }
    }
    None
}

/// Backward-compatible wrapper.
#[allow(dead_code)]
pub fn mask_request_body_with_log(body: &mut Value, log: &mut Option<&mut FilterLogger>) {
    mask_request_body_full(body, 0.0, &[], log);
}

fn mask_message_content_full(
    msg: &mut Value,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> Option<MaskResult> {
    if let Some(obj) = msg.as_object_mut() {
        let role = obj
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let ctx = context.map(|c| format!("{}.{}", c, role));
        if let Some(content) = obj.get_mut("content") {
            return mask_content_full(content, min_score, allowlist, log, ctx.as_deref());
        }
    }
    None
}

fn mask_content_full(
    content: &mut Value,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> Option<MaskResult> {
    match content {
        Value::String(s) => {
            let result = patterns::mask_text_full(s, min_score, allowlist, log, context);
            match result {
                MaskResult::Ok(masked) => {
                    *s = masked;
                    None
                }
                blocked @ MaskResult::Blocked { .. } => Some(blocked),
            }
        }
        Value::Array(arr) => {
            for (i, block) in arr.iter_mut().enumerate() {
                if let Some(obj) = block.as_object_mut() {
                    if obj.get("type").and_then(|v| v.as_str()) == Some("text") {
                        let ctx = context.map(|c| format!("{}.block.{}", c, i));
                        if let Some(text) = obj.get_mut("text") {
                            if let Some(s) = text.as_str() {
                                let result = patterns::mask_text_full(
                                    s,
                                    min_score,
                                    allowlist,
                                    log,
                                    ctx.as_deref(),
                                );
                                match result {
                                    MaskResult::Ok(masked) => {
                                        *text = Value::String(masked);
                                    }
                                    blocked @ MaskResult::Blocked { .. } => return Some(blocked),
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn mask_value_full(
    v: &mut Value,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> Option<MaskResult> {
    match v {
        Value::String(s) => {
            let result = patterns::mask_text_full(s, min_score, allowlist, log, context);
            match result {
                MaskResult::Ok(masked) => {
                    *s = masked;
                    None
                }
                blocked @ MaskResult::Blocked { .. } => Some(blocked),
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                if let Some(blocked) = mask_value_full(item, min_score, allowlist, log, context) {
                    return Some(blocked);
                }
            }
            None
        }
        Value::Object(obj) => {
            for (_, val) in obj.iter_mut() {
                if let Some(blocked) = mask_value_full(val, min_score, allowlist, log, context) {
                    return Some(blocked);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_system_prompt() {
        let mut body = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "system": "Contact admin@example.org for help",
            "messages": []
        });
        mask_request_body(&mut body);
        let system = body["system"].as_str().unwrap();
        assert!(!system.contains("admin@example.org"));
        assert!(system.contains("[masked:email]"));
    }

    #[test]
    fn masks_message_content_string() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Email me at test@example.com"}
            ]
        });
        mask_request_body(&mut body);
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[masked:email]"));
    }

    #[test]
    fn masks_message_content_blocks() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Hello from user@test.com"}]}
            ]
        });
        mask_request_body(&mut body);
        let text = body["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("[masked:email]"));
    }

    #[test]
    fn leaves_empty_messages_unchanged() {
        let mut body = serde_json::json!({
            "model": "claude-3-5-sonnet",
            "messages": []
        });
        mask_request_body(&mut body);
        assert!(body["messages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn leaves_non_text_blocks_unchanged() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png"}}]}
            ]
        });
        mask_request_body(&mut body);
        assert_eq!(body["messages"][0]["content"][0]["type"], "image");
    }

    #[test]
    fn masks_private_key_in_body() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR\n-----END RSA PRIVATE KEY-----"}
            ]
        });
        let result = mask_request_body(&mut body);
        // Should mask, not block
        assert!(result.is_none(), "Should not block");
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[masked:private_key]"), "PEM not masked: {}", content);
    }

    #[test]
    fn respects_min_score() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Number +79991234567"}
            ]
        });
        // Phone score=0.55, with min_score=0.8 should NOT mask
        let result = mask_request_body_full(&mut body, 0.8, &[], &mut None);
        assert!(result.is_none());
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("+79991234567"), "Phone should not be masked at 0.8 threshold");
    }

    #[test]
    fn respects_allowlist() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Contact admin@company.internal"}
            ]
        });
        let allowlist = vec!["admin@company.internal".to_string()];
        mask_request_body_full(&mut body, 0.0, &allowlist, &mut None);
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("admin@company.internal"), "Allowlisted email should not be masked");
    }
}
