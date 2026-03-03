//! Filter logging: records what was masked for audit/debug.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;

/// Collects filter events for a single request.
#[derive(Debug, Default)]
pub struct FilterLogger {
    /// (mask_type, context) -> count. Context is "" for no context.
    events: HashMap<(String, String), u32>,
    /// Whether to include context in each record (detailed mode).
    detailed: bool,
    /// Whether to log SHA256 hashes of matched values for audit.
    audit_hash: bool,
    /// Audit entries: (mask_type, sha256_hash).
    audit_entries: Vec<(String, String)>,
}

impl FilterLogger {
    pub fn new(detailed: bool) -> Self {
        Self {
            events: HashMap::new(),
            detailed,
            audit_hash: false,
            audit_entries: Vec::new(),
        }
    }

    /// Create with audit hashing enabled.
    pub fn with_audit(detailed: bool) -> Self {
        Self {
            events: HashMap::new(),
            detailed,
            audit_hash: true,
            audit_entries: Vec::new(),
        }
    }

    /// Record that `count` occurrences of `mask_type` were masked.
    /// `context` is optional (e.g. "system", "messages.0.user").
    pub fn record(&mut self, mask_type: &str, count: u32, context: Option<&str>) {
        if count == 0 {
            return;
        }
        let ctx = context.unwrap_or("").to_string();
        *self
            .events
            .entry((mask_type.to_string(), ctx))
            .or_insert(0) += count;
    }

    /// Record a matched value for audit logging (stores SHA256 hash only).
    pub fn record_audit(&mut self, mask_type: &str, matched_value: &str) {
        if !self.audit_hash {
            return;
        }
        let mut hasher = Sha256::new();
        hasher.update(matched_value.as_bytes());
        let hash = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(hex, "{:02x}", byte);
        }
        self.audit_entries.push((mask_type.to_string(), hex));
    }

    /// Returns true if any events were recorded.
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Aggregate counts by mask_type (ignore context).
    pub fn summary(&self) -> HashMap<String, u32> {
        let mut m: HashMap<String, u32> = HashMap::new();
        for ((mask_type, _), count) in &self.events {
            *m.entry(mask_type.clone()).or_insert(0) += count;
        }
        m
    }

    /// Returns string descriptions of all events (for web UI).
    pub fn events(&self) -> Vec<String> {
        self.events
            .iter()
            .map(|((mask_type, context), count)| {
                if context.is_empty() {
                    format!("{}: {} match(es)", mask_type, count)
                } else {
                    format!("{}: {} match(es) in {}", mask_type, count, context)
                }
            })
            .collect()
    }

    /// Emit tracing events for collected data.
    pub fn emit(&self, path: &str) {
        if self.events.is_empty() {
            return;
        }

        if self.detailed {
            for ((mask_type, context), count) in &self.events {
                let ctx = if context.is_empty() {
                    path.to_string()
                } else {
                    format!("{}/{}", path, context)
                };
                tracing::debug!(
                    mask_type = %mask_type,
                    count = %count,
                    context = %ctx,
                    "filter applied"
                );
            }
        } else {
            let summary = self.summary();
            let parts: Vec<String> = summary
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            tracing::info!(
                path = %path,
                filters = %parts.join(", "),
                "filter applied"
            );
        }

        // Emit audit entries
        for (mask_type, hash) in &self.audit_entries {
            tracing::info!(
                mask_type = %mask_type,
                sha256 = %hash,
                path = %path,
                "audit: masked value"
            );
        }
    }
}
