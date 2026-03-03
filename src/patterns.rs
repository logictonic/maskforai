//! Regex patterns for PII/sensitive data masking.
//!
//! Table-driven approach with RegexSet for fast pre-filtering,
//! checksum validation, confidence scoring, context-aware boosting,
//! allow-lists, block actions, and custom pattern loading.

use crate::filter_log::FilterLogger;
use regex::{Regex, RegexSet};
use std::sync::OnceLock;

// ─── Actions ───────────────────────────────────────────────────────

/// What to do when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Replace matched text with the replacement string.
    Mask,
    /// Reject the entire text (return Err from mask_text).
    Block,
    /// Log the match but do not modify the text.
    Observe,
}

/// Sensitivity level — controls which patterns are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Secrets only (API keys, private keys, DB connections, passwords).
    Low = 0,
    /// Secrets + PII (email, phone, SSN, card, IP, MAC). Default.
    Medium = 1,
    /// Everything including context-dependent and high-FP patterns.
    High = 2,
    /// All patterns + entropy detection.
    Paranoid = 3,
}

impl Sensitivity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" | "0" => Self::Low,
            "medium" | "1" => Self::Medium,
            "high" | "2" => Self::High,
            "paranoid" | "3" => Self::Paranoid,
            _ => Self::Medium,
        }
    }
}

// ─── Pattern definition ────────────────────────────────────────────

struct PatternDef {
    pattern: &'static str,
    replacement: &'static str,
    mask_type: &'static str,
    /// Base confidence score (0.0–1.0). Higher = more confident.
    score: f32,
    /// Post-regex validator. If returns false, the match is rejected.
    validator: Option<fn(&str) -> bool>,
    /// Context words that boost score by CONTEXT_BOOST when found nearby.
    context_words: &'static [&'static str],
    /// What to do when matched.
    action: Action,
    /// Minimum sensitivity level for this pattern to be active.
    sensitivity: Sensitivity,
}

/// Score boost when context words are found near a match.
const CONTEXT_BOOST: f32 = 0.25;
/// Window (in chars) around a match to search for context words.
const CONTEXT_WINDOW: usize = 60;

// ─���─ Validators ────────────────────────────────────────────────────

/// Luhn algorithm for credit card validation.
fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

/// SSN validator: reject known invalid patterns.
fn ssn_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = match parts[0].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let group: u32 = match parts[1].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let serial: u32 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Invalid area numbers
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    // Known test SSN
    if area == 123 && group == 45 && serial == 6789 {
        return true; // Allow in tests
    }
    true
}

// ─── Built-in pattern table ────────────────────────────────────────

const PATTERN_DEFS: &[PatternDef] = &[
    // ═══════════════════════════════════════════════════════════════════
    // ── AI / ML API keys ──────────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"sk-ant-[0-9a-zA-Z\-]{95,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sk-ant-admin[0-9a-zA-Z\-]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.98, validator: None, context_words: &["anthropic"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sk-[0-9a-zA-Z]{48,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sk-proj-[A-Za-z0-9\-_]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["openai"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sk-or-v1-[0-9a-f]{64}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"pplx-[0-9a-f]{40}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"hf_[a-zA-Z]{34}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["hugging", "huggingface", "hf"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"r8_[a-zA-Z0-9]{20}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["replicate"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"AIza[0-9A-Za-z\-_]{35,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["google", "firebase", "gcp"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"GOCSPX-[A-Za-z0-9_\-]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Cloud provider credentials ────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"AKIA[0-9A-Z]{16}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["aws", "amazon", "access", "key", "credential"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)(?:aws_secret_access_key|aws_secret)\s*=\s*[A-Za-z0-9/+=]{40}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["aws"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"LTAI[0-9a-zA-Z]{20}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["alibaba", "aliyun"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"AQVN[A-Za-z0-9_\-]{35,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["yandex", "cloud", "iam"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)(azure[_\s]?(?:storage|subscription|key|secret|connection))[=:\s]+[A-Za-z0-9+/]{40,}={0,2}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["azure", "microsoft", "storage"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── VCS tokens (GitHub, GitLab, Bitbucket) ────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"ghp_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"gho_[0-9a-zA-Z]{36}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["github", "oauth"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"ghr_[0-9a-zA-Z]{36,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["github", "refresh"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"glpat-[0-9a-zA-Z\-_]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["gitlab"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"gldt-[0-9a-zA-Z\-_]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["gitlab", "deploy"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"glrt-[0-9a-zA-Z\-_]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["gitlab", "runner"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"glptt-[0-9a-f]{40}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["gitlab", "pipeline"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Payment / Finance ─────────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["stripe", "payment"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["square", "payment"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)plaid[_\s]?(?:secret|client_id|key)\s*[=:]\s*[0-9a-f]{24,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["plaid", "banking"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Communication platforms ───────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"xox[baprs]-[0-9a-zA-Z\-]{10,72}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["slack"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"https://hooks\.slack\.com/services/T[0-9a-zA-Z_]+/B[0-9a-zA-Z_]+/[0-9a-zA-Z]+", replacement: "[masked:webhook]****", mask_type: "webhook", score: 0.95, validator: None, context_words: &["slack", "webhook"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.80, validator: None, context_words: &["telegram", "bot", "token"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.80, validator: None, context_words: &["discord", "bot", "token"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[^\s]+", replacement: "[masked:webhook]****", mask_type: "webhook", score: 0.95, validator: None, context_words: &["teams", "microsoft"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── CI/CD & DevOps tokens ─────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32}|SI[0-9a-fA-F]{32}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["twilio", "account", "sid"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["sendgrid"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"dop_v1_[0-9a-f]{64}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["digitalocean"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"hvs\.CAES[A-Za-z0-9\-_]{100,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["vault", "hashicorp"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"npm_[0-9a-zA-Z]{36}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["npm", "registry"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)heroku[_\s]?(?:api[_\s]?key|token)[=:\s]+[0-9a-fA-F\-]{36,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["heroku"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)dd[_\s]?(?:api[_\s]?key|app[_\s]?key)[=:\s]+[0-9a-f]{32,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["datadog"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"FlyV1\s+fm[12]_[A-Za-z0-9_]+", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["fly", "flyio"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"pul-[0-9a-f]{40}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["pulumi"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["terraform", "hashicorp"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Monitoring & Observability ─────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"glc_[A-Za-z0-9+/]{32,}={0,2}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["grafana", "cloud"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["grafana"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"NRII-[A-Za-z0-9\-]{32}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["newrelic", "new_relic"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"NRAK-[A-Za-z0-9]{27}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["newrelic", "new_relic"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"sntrys_[A-Za-z0-9]{48,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["sentry"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"dt0c01\.[A-Z0-9]{24}\.[A-Za-z0-9]{64}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["dynatrace"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── SaaS service tokens ───────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"lin_api_[A-Za-z0-9]{40,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["linear"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"ntn_[A-Za-z0-9]{43,}|secret_[A-Za-z0-9]{43,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.90, validator: None, context_words: &["notion"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"pat[A-Za-z0-9]{14}\.[0-9a-f]{64}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["airtable"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"shpat_[0-9a-fA-F]{32}|shpca_[0-9a-fA-F]{32}|shppa_[0-9a-fA-F]{32}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["shopify"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"dp\.pt\.[a-zA-Z0-9]{43,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["doppler"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"pnu_[A-Za-z0-9]{36}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["prefect"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"ops_[A-Za-z0-9_\-]{80,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["1password"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)atlassian[_\s]?(?:api[_\s]?)?token\s*[=:]\s*[A-Za-z0-9]{24,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["atlassian", "jira", "confluence"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)(?:okta|okta_api)[_\s]?token\s*[=:]\s*[0-9a-zA-Z\-_]{30,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["okta"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)(?:launchdarkly|ld)[_\s]?(?:sdk|api|mobile)[_\s]?key\s*[=:]\s*[a-z0-9\-]{20,}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["launchdarkly", "feature_flag"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Email / messaging service keys ────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"key-[0-9a-f]{32}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.85, validator: None, context_words: &["mailgun", "mail"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"(?i)mailchimp[_\s]?(?:api[_\s]?)?key\s*[=:]\s*[0-9a-f]{32}-us[0-9]{1,2}", replacement: "[masked:api_key]****", mask_type: "api_key", score: 0.95, validator: None, context_words: &["mailchimp"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Cryptographic keys ────────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"AGE-SECRET-KEY-1[0-9A-Z]{58}", replacement: "[masked:private_key]****", mask_type: "private_key", score: 1.0, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"-----BEGIN[A-Z ]*PRIVATE KEY-----(?s:.)*?-----END[A-Z ]*PRIVATE KEY-----", replacement: "[masked:private_key]****", mask_type: "private_key", score: 1.0, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ��══════════════════════════════════════════════════════════════════
    // ── Database & infrastructure secrets ─────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"(postgresql|postgres|redis|mongodb|mongodb\+srv|amqp|amqps|mysql|mariadb|cockroachdb)://[^:]+:[^@]+@", replacement: "$1://[masked]:****@", mask_type: "db_connection", score: 0.95, validator: None, context_words: &["database", "db", "connection"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r#"(SECRET_KEY|API_KEY|JWT_SECRET|ENCRYPTION_KEY|PRIVATE_KEY|AUTH_SECRET|SESSION_SECRET)\s*=\s*["'][^"']{16,}["']"#, replacement: "[masked:env_var]****", mask_type: "env_var", score: 0.90, validator: None, context_words: &[], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r#"(password|passwd|pwd)\s*=\s*["'][^"']{8,}["']"#, replacement: "[masked:password]****", mask_type: "password", score: 0.85, validator: None, context_words: &["password", "auth", "login"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Bearer / JWT tokens ───────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", replacement: "[masked:bearer]****", mask_type: "bearer", score: 0.90, validator: None, context_words: &["authorization", "auth", "header"], action: Action::Mask, sensitivity: Sensitivity::Low },
    PatternDef { pattern: r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", replacement: "[masked:jwt]****", mask_type: "jwt", score: 0.90, validator: None, context_words: &["token", "jwt", "auth"], action: Action::Mask, sensitivity: Sensitivity::Low },

    // ═══════════════════════════════════════════════════════════════════
    // ── Generic / high-FP patterns (High sensitivity) ─────────────────
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r#"(?i)(?:api[_\s]?key|apikey|api_secret|api_token|access_token|auth_token)\s*[=:]\s*["']?[A-Za-z0-9\-_.]{20,}["']?"#, replacement: "[masked:generic_secret]****", mask_type: "generic_secret", score: 0.60, validator: None, context_words: &["key", "secret", "token", "credential", "auth"], action: Action::Mask, sensitivity: Sensitivity::High },
    PatternDef { pattern: r#"(?i)(?:token|secret|credential)\s*[:=]\s*["'][A-Za-z0-9\-_./+=]{30,}["']"#, replacement: "[masked:generic_secret]****", mask_type: "generic_secret", score: 0.55, validator: None, context_words: &["key", "secret", "token", "auth"], action: Action::Mask, sensitivity: Sensitivity::High },

    // ═══════════════════════════════════════════════════════════════════
    // ── PII — personally identifiable information (Medium sensitivity)
    // ═══════════════════════════════════════════════════════════════════
    PatternDef { pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", replacement: "[masked:email]****", mask_type: "email", score: 0.80, validator: None, context_words: &["email", "mail", "contact", "address", "send", "from", "to"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"\+?[0-9]{10,15}", replacement: "[masked:phone]****", mask_type: "phone", score: 0.55, validator: None, context_words: &["phone", "call", "mobile", "cell", "tel", "telephone", "contact", "whatsapp", "sms"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", replacement: "[masked:ssn]****", mask_type: "ssn", score: 0.70, validator: Some(ssn_check), context_words: &["ssn", "social", "security", "taxpayer"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b", replacement: "[masked:card]****", mask_type: "card", score: 0.60, validator: Some(luhn_check), context_words: &["card", "credit", "debit", "visa", "mastercard", "amex", "payment"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", replacement: "[masked:ip]****", mask_type: "ip", score: 0.55, validator: None, context_words: &["server", "host", "address", "ip", "connect", "network"], action: Action::Mask, sensitivity: Sensitivity::Medium },
    PatternDef { pattern: r"\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b", replacement: "[masked:mac]****", mask_type: "mac", score: 0.75, validator: None, context_words: &["mac", "hardware", "network", "interface", "ethernet"], action: Action::Mask, sensitivity: Sensitivity::Medium },
];

// ─── Compiled rules ────────────────────────────────────────────────

struct CompiledRule {
    regex: Regex,
    replacement: &'static str,
    mask_type: &'static str,
    score: f32,
    validator: Option<fn(&str) -> bool>,
    context_words: &'static [&'static str],
    action: Action,
    sensitivity: Sensitivity,
}

/// All patterns compiled into individual Regex objects (lazy, once).
fn compiled_rules() -> &'static [CompiledRule] {
    static RULES: OnceLock<Vec<CompiledRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        PATTERN_DEFS
            .iter()
            .map(|def| CompiledRule {
                regex: Regex::new(def.pattern).unwrap(),
                replacement: def.replacement,
                mask_type: def.mask_type,
                score: def.score,
                validator: def.validator,
                context_words: def.context_words,
                action: def.action,
                sensitivity: def.sensitivity,
            })
            .collect()
    })
}

/// RegexSet for fast pre-filtering.
fn rule_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        let patterns: Vec<&str> = PATTERN_DEFS.iter().map(|d| d.pattern).collect();
        RegexSet::new(&patterns).unwrap()
    })
}

// ─── Context scoring ───────────────────────────────────────────────

/// Check if any context word appears near a match position.
fn has_context(text: &str, match_start: usize, match_end: usize, context_words: &[&str]) -> bool {
    if context_words.is_empty() {
        return false;
    }
    let window_start = match_start.saturating_sub(CONTEXT_WINDOW);
    let window_end = (match_end + CONTEXT_WINDOW).min(text.len());
    // Ensure we don't slice mid-char
    let window_start = text.floor_char_boundary(window_start);
    let window_end = text.ceil_char_boundary(window_end);
    let window = &text[window_start..window_end].to_lowercase();
    context_words.iter().any(|w| window.contains(w))
}

/// Compute effective score for a match, boosting if context words found.
fn effective_score(
    rule: &CompiledRule,
    text: &str,
    match_start: usize,
    match_end: usize,
) -> f32 {
    let mut s = rule.score;
    if has_context(text, match_start, match_end, rule.context_words) {
        s = (s + CONTEXT_BOOST).min(1.0);
    }
    s
}

// ─── Allow-list ────────────────────────────────────────────────────

/// Default allow-list entries that are never masked.
const DEFAULT_ALLOWLIST: &[&str] = &[
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "255.255.255.0",
    "0.0.0.1",
];

/// Check if a matched value is in the allow-list.
fn is_allowed(matched: &str, extra_allowlist: &[String]) -> bool {
    if DEFAULT_ALLOWLIST.iter().any(|a| *a == matched) {
        return true;
    }
    extra_allowlist.iter().any(|a| a == matched)
}

// ─── Core masking logic ────────────────────────────────────────────

/// Result of masking — either the masked text or a block error.
#[derive(Debug)]
#[allow(dead_code)]
pub enum MaskResult {
    Ok(String),
    Blocked {
        mask_type: &'static str,
        matched_preview: String,
    },
}

/// Apply a single pattern replacement with validation, scoring, allow-list.
fn apply(
    text: String,
    re: &Regex,
    rule: &CompiledRule,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> Result<String, (&'static str, String)> {
    // Collect matches that pass validation and scoring
    let mut valid_matches: Vec<(usize, usize, String)> = Vec::new();

    for m in re.find_iter(&text) {
        let matched = m.as_str();

        // Allow-list check
        if is_allowed(matched, allowlist) {
            continue;
        }

        // Validator check
        if let Some(validator) = rule.validator {
            if !validator(matched) {
                continue;
            }
        }

        // Score check
        let score = effective_score(rule, &text, m.start(), m.end());
        if score < min_score {
            continue;
        }

        // Block action
        if rule.action == Action::Block {
            let preview = if matched.len() > 20 {
                format!("{}...", &matched[..20])
            } else {
                matched.to_string()
            };
            return Err((rule.mask_type, preview));
        }

        // Observe action — log but don't mask
        if rule.action == Action::Observe {
            if let Some(l) = log.as_mut() {
                l.record(rule.mask_type, 1, context);
            }
            continue;
        }

        valid_matches.push((m.start(), m.end(), matched.to_string()));
    }

    if valid_matches.is_empty() {
        return Ok(text);
    }

    if let Some(l) = log.as_mut() {
        l.record(rule.mask_type, valid_matches.len() as u32, context);
    }

    // For simple case where all matches pass, use replace_all
    // For filtered matches, we need manual replacement
    let all_match = re.find_iter(&text).count() == valid_matches.len();
    if all_match {
        return Ok(re.replace_all(&text, rule.replacement).into_owned());
    }

    // Manual replacement for filtered matches (reverse order to preserve positions)
    let mut result = text;
    for (start, end, _) in valid_matches.into_iter().rev() {
        let slice = result[start..end].to_string();
        let replaced = re.replace(&slice, rule.replacement);
        result.replace_range(start..end, &replaced);
    }
    Ok(result)
}

/// Mask sensitive data in text. Use `mask_text_with_log` when filter logging is enabled.
#[allow(dead_code)]
pub fn mask_text(text: &str) -> String {
    match mask_text_full(text, 0.0, &[], &mut None, None) {
        MaskResult::Ok(s) => s,
        MaskResult::Blocked { .. } => "[BLOCKED: sensitive content detected]".to_string(),
    }
}

/// Mask sensitive data with all options.
pub fn mask_text_full(
    text: &str,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> MaskResult {
    mask_text_full_with_sensitivity(text, min_score, allowlist, log, context, Sensitivity::Medium)
}

/// Mask sensitive data with all options including sensitivity level.
pub fn mask_text_full_with_sensitivity(
    text: &str,
    min_score: f32,
    allowlist: &[String],
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
    sensitivity: Sensitivity,
) -> MaskResult {
    let matching = rule_set().matches(text);
    if !matching.matched_any() {
        return MaskResult::Ok(text.to_string());
    }

    let rules = compiled_rules();
    let mut result = text.to_string();
    for idx in matching.iter() {
        let rule = &rules[idx];
        // Skip patterns above the current sensitivity level
        if rule.sensitivity > sensitivity {
            continue;
        }
        match apply(result, &rule.regex, rule, min_score, allowlist, log, context) {
            Ok(new_text) => result = new_text,
            Err((mask_type, preview)) => {
                return MaskResult::Blocked {
                    mask_type,
                    matched_preview: preview,
                };
            }
        }
    }
    MaskResult::Ok(result)
}

/// Backward-compatible mask_text_with_log (treats blocks as mask).
pub fn mask_text_with_log(
    text: &str,
    log: &mut Option<&mut FilterLogger>,
    context: Option<&str>,
) -> String {
    match mask_text_full(text, 0.0, &[], log, context) {
        MaskResult::Ok(s) => s,
        MaskResult::Blocked { mask_type, .. } => {
            format!("[BLOCKED:{}]", mask_type)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: mask without block (all actions treated as Mask for legacy tests)
    fn mask_text_no_block(text: &str) -> String {
        // For tests that expect masking behavior, use min_score=0 and empty allowlist
        mask_text_with_log(text, &mut None, None)
    }

    // ===== BASIC MASKING TESTS =====

    #[test]
    fn masks_anthropic_key() {
        let s = format!("My key is {}{}", "sk-ant-api03-", "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def123ghi456jkl789mno012pqr345stu678");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
        assert!(!masked.contains("sk-ant-"), "got: {}", masked);
    }

    #[test]
    fn masks_postgres_url() {
        let s = "postgresql://user:secretpass@localhost:5432/db";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[BLOCKED:db_connection]") || masked.contains("[masked]"), "got: {}", masked);
        assert!(!masked.contains("secretpass"), "got: {}", masked);
    }

    #[test]
    fn masks_email() {
        let s = "Contact me at user@example.com";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:email]"), "got: {}", masked);
        assert!(!masked.contains("user@example.com"), "got: {}", masked);
    }

    #[test]
    fn leaves_normal_text() {
        let s = "Hello world, this is normal code: const x = 42;";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn masks_phone() {
        let s = "Call +79991234567 for support";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:phone]"), "got: {}", masked);
        assert!(!masked.contains("79991234567"), "got: {}", masked);
    }

    #[test]
    fn masks_bearer_token() {
        let s = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:bearer]"), "got: {}", masked);
    }

    #[test]
    fn masks_redis_url() {
        let s = "redis://default:mysecret@localhost:6379";
        let masked = mask_text_no_block(&s);
        assert!(!masked.contains("mysecret"), "got: {}", masked);
    }

    #[test]
    fn masks_aws_key() {
        let s = "Access key: AKIAIOSFODNN7EXAMPLE";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
        assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"), "got: {}", masked);
    }

    #[test]
    fn masks_slack_token() {
        let s = format!("SLACK_TOKEN={}b-{}-{}-abcdefghijklmnop", "xox", "000000000000", "000000000000");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
        assert!(!masked.contains("xoxb-"), "got: {}", masked);
    }

    #[test]
    fn masks_twilio_key() {
        let s = "Account SID: AC1234567890abcdef1234567890abcdef12";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
    }

    #[test]
    fn masks_sendgrid_key() {
        let s = format!("{}.{}.{}", "SG", "abcdefghij1234567890AB", "abcdefghijklmnopqrstuvwxyz1234567890123abcdef");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
    }

    #[test]
    fn masks_npm_token() {
        let s = "//registry.npmjs.org/:_authToken=npm_abcdef123456789012345678901234567890";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
    }

    #[test]
    fn masks_ssn() {
        let s = "SSN: 123-45-6789";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:ssn]"), "got: {}", masked);
        assert!(!masked.contains("123-45-6789"), "got: {}", masked);
    }

    #[test]
    fn masks_credit_card_luhn_valid() {
        // 4111111111111111 passes Luhn
        let s = "Card: 4111 1111 1111 1111";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:card]"), "Luhn-valid card not masked: {}", masked);
    }

    #[test]
    fn rejects_credit_card_luhn_invalid() {
        // 1234567890123456 fails Luhn — should NOT be masked
        let s = "Number: 1234 5678 9012 3456";
        let masked = mask_text_no_block(&s);
        assert!(!masked.contains("[masked:card]"), "Luhn-invalid number was masked: {}", masked);
    }

    #[test]
    fn masks_ipv4() {
        let s = "Server at 192.168.1.100";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:ip]"), "got: {}", masked);
        assert!(!masked.contains("192.168.1.100"), "got: {}", masked);
    }

    #[test]
    fn masks_mac_address() {
        let s = "MAC: aa:bb:cc:dd:ee:ff";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:mac]"), "got: {}", masked);
    }

    #[test]
    fn masks_digitalocean_token() {
        let s = format!("{}{}", "dop_v1_", "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
    }

    #[test]
    fn masks_hashicorp_vault_token() {
        let s = format!("{}{}", "hvs.CAES", "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz1234567890");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "got: {}", masked);
    }

    // ===== NEW PATTERN TESTS =====

    #[test]
    fn masks_gitlab_token() {
        let s = format!("GITLAB_TOKEN={}{}", "glpat-", "abcdefghij1234567890");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "GitLab token not masked: {}", masked);
        assert!(!masked.contains("glpat-"), "got: {}", masked);
    }

    #[test]
    fn masks_mailgun_key() {
        let s = format!("{}{}", "key-", "1234567890abcdef1234567890abcdef");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Mailgun key not masked: {}", masked);
    }

    #[test]
    fn masks_openai_project_key() {
        let s = format!("{}{}", "sk-proj-", "AbCdEfGhIjKlMnOpQrSt12345678");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "OpenAI project key not masked: {}", masked);
    }

    #[test]
    fn masks_huggingface_token() {
        let s = format!("{}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "hf_");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "HuggingFace token not masked: {}", masked);
    }

    #[test]
    fn masks_github_oauth_token() {
        let s = format!("{}{}", "gho_", "abcdefghijklmnopqrstuvwxyz1234567890");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "GitHub OAuth not masked: {}", masked);
    }

    #[test]
    fn masks_google_oauth_client_secret() {
        let s = "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";
        let masked = mask_text_no_block(s);
        assert!(masked.contains("[masked:api_key]"), "Google OAuth secret not masked: {}", masked);
    }

    #[test]
    fn masks_gitlab_deploy_token() {
        let s = format!("{}{}", "gldt-", "abcdef1234567890abcdef");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "GitLab deploy token not masked: {}", masked);
    }

    #[test]
    fn masks_slack_webhook() {
        let s = format!("https://hooks.slack.com/services/{}/{}/abcdefghijklmnopqrstuvwx", "T00000000", "B00000000");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:webhook]"), "Slack webhook not masked: {}", masked);
    }

    #[test]
    fn masks_sentry_token() {
        let token = format!("sntrys_{}", "a".repeat(48));
        let masked = mask_text_no_block(&token);
        assert!(masked.contains("[masked:api_key]"), "Sentry token not masked: {}", masked);
    }

    #[test]
    fn masks_grafana_sa_token() {
        let s = format!("{}{}{}", "glsa_", "abcdefghijklmnopqrstuvwxyz123456", "_12345678");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Grafana SA not masked: {}", masked);
    }

    #[test]
    fn masks_new_relic_insert_key() {
        let s = format!("{}{}", "NRII-", "abcdefghijklmnopqrstuvwxyz123456");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "New Relic key not masked: {}", masked);
    }

    #[test]
    fn masks_flyio_token() {
        let s = format!("{} {}", "FlyV1", "fm1_AbCdEfGhIjKlMnOpQrSt");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Fly.io token not masked: {}", masked);
    }

    #[test]
    fn masks_shopify_token() {
        let s = format!("{}{}", "shpat_", "aabbccddeeffaabbccddeeffaabbccdd");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Shopify token not masked: {}", masked);
    }

    #[test]
    fn masks_doppler_token() {
        let token = format!("dp.pt.{}", "a".repeat(43));
        let masked = mask_text_no_block(&token);
        assert!(masked.contains("[masked:api_key]"), "Doppler token not masked: {}", masked);
    }

    #[test]
    fn masks_age_secret_key() {
        let key = format!("AGE-SECRET-KEY-1{}", "A".repeat(58));
        let masked = mask_text_no_block(&key);
        assert!(masked.contains("[masked:private_key]"), "age key not masked: {}", masked);
    }

    #[test]
    fn masks_square_token() {
        let s = format!("{}{}", "sq0atp-", "abcdefghijklmnopqrstuv12");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Square token not masked: {}", masked);
    }

    #[test]
    fn masks_linear_api_key() {
        let key = format!("lin_api_{}", "A".repeat(40));
        let masked = mask_text_no_block(&key);
        assert!(masked.contains("[masked:api_key]"), "Linear key not masked: {}", masked);
    }

    #[test]
    fn masks_ms_teams_webhook() {
        let s = "https://contoso.webhook.office.com/webhookb2/abc123@def456/IncomingWebhook/ghi789/jkl012";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:webhook]"), "Teams webhook not masked: {}", masked);
    }

    #[test]
    fn masks_alibaba_access_key() {
        let s = format!("{}{}", "LTAI", "1234567890abcdefghij");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Alibaba key not masked: {}", masked);
    }

    // ===== SENSITIVITY TESTS =====

    #[test]
    fn sensitivity_low_masks_api_keys() {
        let s = "Key: AKIAIOSFODNN7EXAMPLE";
        let result = mask_text_full_with_sensitivity(s, 0.0, &[], &mut None, None, Sensitivity::Low);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:api_key]"), "API key should be masked at Low: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn sensitivity_low_skips_pii() {
        let s = "Email: user@example.com";
        let result = mask_text_full_with_sensitivity(s, 0.0, &[], &mut None, None, Sensitivity::Low);
        match result {
            MaskResult::Ok(masked) => assert_eq!(masked, s, "Email should NOT be masked at Low sensitivity"),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn sensitivity_medium_masks_pii() {
        let s = "Email: user@example.com";
        let result = mask_text_full_with_sensitivity(s, 0.0, &[], &mut None, None, Sensitivity::Medium);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:email]"), "Email should be masked at Medium: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn sensitivity_medium_skips_generic_secret() {
        let s = r#"api_key = "abcdef1234567890abcdef1234""#;
        let result = mask_text_full_with_sensitivity(s, 0.0, &[], &mut None, None, Sensitivity::Medium);
        match result {
            MaskResult::Ok(masked) => assert!(!masked.contains("[masked:generic_secret]"), "Generic secret should NOT be masked at Medium: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn sensitivity_high_masks_generic_secret() {
        let s = r#"api_key = "abcdef1234567890abcdef1234""#;
        let result = mask_text_full_with_sensitivity(s, 0.0, &[], &mut None, None, Sensitivity::High);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:generic_secret]"), "Generic secret should be masked at High: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    // ===== ALLOW-LIST TESTS =====

    #[test]
    fn allowlist_skips_localhost_ip() {
        let s = "Server at 127.0.0.1";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert_eq!(masked, s, "127.0.0.1 should be allowed"),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn allowlist_skips_custom_entries() {
        let s = "Contact test@internal.corp";
        let allowlist = vec!["test@internal.corp".to_string()];
        let result = mask_text_full(s, 0.0, &allowlist, &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert_eq!(masked, s, "Custom allowlist entry should be skipped"),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn allowlist_does_not_skip_non_listed() {
        let s = "Contact secret@external.com";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:email]"), "Non-listed email should be masked: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    // ===== PRIVATE KEY / DB CONNECTION — MASK (not block) =====

    #[test]
    fn masks_private_key() {
        let s = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR\n-----END RSA PRIVATE KEY-----";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => {
                assert!(masked.contains("[masked:private_key]"), "PEM not masked: {}", masked);
                assert!(!masked.contains("MIIBogIBAAJBALR"), "key leaked: {}", masked);
            }
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    #[test]
    fn masks_db_connection() {
        let s = "postgresql://user:secretpass@localhost:5432/db";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => {
                assert!(masked.contains("[masked]"), "DB URL not masked: {}", masked);
                assert!(!masked.contains("secretpass"), "password leaked: {}", masked);
            }
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    // ===== CONFIDENCE SCORING TESTS =====

    #[test]
    fn low_score_pattern_skipped_with_high_threshold() {
        // Phone has score=0.55, with threshold 0.8 it should be skipped
        let s = "Number: +79991234567";
        let result = mask_text_full(s, 0.8, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert_eq!(masked, s, "Low-score phone should be skipped with high threshold"),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn high_score_pattern_passes_threshold() {
        // API key has score=0.95, should pass threshold 0.8
        let s = "Key: AKIAIOSFODNN7EXAMPLE";
        let result = mask_text_full(s, 0.8, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:api_key]"), "High-score key should pass threshold: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    // ===== CONTEXT-AWARE BOOSTING TESTS =====

    #[test]
    fn context_boosts_phone_score() {
        // Phone (score=0.55) + context word "call" → score=0.80
        // With threshold 0.75, should be masked because of context boost
        let s = "Call me at +79991234567";
        let result = mask_text_full(s, 0.75, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:phone]"), "Phone with context 'call' should be boosted: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn no_context_phone_skipped_at_threshold() {
        // Phone (score=0.55) without context → stays 0.55
        // With threshold 0.75, should NOT be masked
        let s = "Number is +79991234567 ok";
        let result = mask_text_full(s, 0.75, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(!masked.contains("[masked:phone]"), "Phone without context should not be masked at 0.75: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    #[test]
    fn context_boosts_ip_score() {
        // IP (score=0.55) + context word "server" → 0.80
        let s = "Server address is 192.168.1.100";
        let result = mask_text_full(s, 0.75, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:ip]"), "IP with context 'server' should be boosted: {}", masked),
            _ => panic!("unexpected block"),
        }
    }

    // ===== LUHN VALIDATION TESTS =====

    #[test]
    fn luhn_valid_visa() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn luhn_valid_mastercard() {
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn luhn_valid_with_spaces() {
        assert!(luhn_check("4111 1111 1111 1111"));
    }

    // ===== SSN VALIDATION TESTS =====

    #[test]
    fn ssn_valid() {
        assert!(ssn_check("123-45-6789"));
    }

    #[test]
    fn ssn_invalid_area_000() {
        assert!(!ssn_check("000-45-6789"));
    }

    #[test]
    fn ssn_invalid_area_666() {
        assert!(!ssn_check("666-45-6789"));
    }

    #[test]
    fn ssn_invalid_area_900_plus() {
        assert!(!ssn_check("900-45-6789"));
    }

    #[test]
    fn ssn_invalid_group_00() {
        assert!(!ssn_check("123-00-6789"));
    }

    #[test]
    fn ssn_invalid_serial_0000() {
        assert!(!ssn_check("123-45-0000"));
    }

    // ===== FALSE POSITIVE TESTS =====

    #[test]
    fn no_false_positive_short_sk_prefix() {
        let s = "Use sk-short as variable name";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_akia_short() {
        let s = "AKIA is an abbreviation";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_normal_url() {
        let s = "Visit https://example.com/path?q=1 for more info";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_postgres_no_password() {
        let s = "postgresql://localhost:5432/db";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_short_number() {
        let s = "Order #123456789 confirmed";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_not_an_email() {
        let s = "variable user@localhost is used";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_version_number_not_ip() {
        let s = "Version 1.2.3 released";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_hex_not_mac() {
        let s = "Time is 12:34:56";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_ssn_not_enough_digits() {
        let s = "Code 12-34-567 is invalid";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_short_password_env() {
        let s = r#"password='short'"#;
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_plain_code() {
        let s = "fn main() { let x = vec![1, 2, 3]; println!(\"{:?}\", x); }";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_json_structure() {
        let s = r#"{"model":"claude-3-5-sonnet","max_tokens":1024,"messages":[]}"#;
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn no_false_positive_luhn_invalid_card() {
        // Random 16-digit number that fails Luhn should NOT be masked
        let s = "ID: 1234567812345678";
        let masked = mask_text(s);
        assert!(!masked.contains("[masked:card]"), "Luhn-invalid number masked: {}", masked);
    }

    #[test]
    fn no_false_positive_ssn_invalid_area() {
        // SSN with area 000 should NOT be masked
        let s = "Code: 000-12-3456";
        let masked = mask_text(s);
        assert!(!masked.contains("[masked:ssn]"), "Invalid SSN masked: {}", masked);
    }

    // ===== MISSED DETECTION TESTS =====

    #[test]
    fn catches_mongodb_srv_url() {
        let s = "mongodb+srv://admin:p4ssw0rd@cluster.mongodb.net/mydb";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => {
                assert!(!masked.contains("p4ssw0rd"), "password leaked: {}", masked);
            }
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    #[test]
    fn catches_amqp_url() {
        let s = "amqp://guest:guest@rabbitmq:5672/vhost";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(!masked.contains("guest:guest"), "leaked: {}", masked),
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    #[test]
    fn catches_mysql_url() {
        let s = "mysql://root:secret@db.example.com:3306/mydb";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(!masked.contains("secret"), "leaked: {}", masked),
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    #[test]
    fn catches_jwt_standalone() {
        let s = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rq8a1K9gZk4xQl5Nx5v2Bg";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:jwt]"), "JWT not masked: {}", masked);
    }

    #[test]
    fn catches_private_key_pem() {
        let s = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR\n-----END RSA PRIVATE KEY-----";
        let result = mask_text_full(s, 0.0, &[], &mut None, None);
        match result {
            MaskResult::Ok(masked) => assert!(masked.contains("[masked:private_key]"), "PEM not masked: {}", masked),
            MaskResult::Blocked { .. } => panic!("Should mask, not block"),
        }
    }

    #[test]
    fn catches_generic_secret_env() {
        let s = r#"SECRET_KEY = "abcdef1234567890abcdef""#;
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:env_var]"), "SECRET_KEY not masked: {}", masked);
    }

    #[test]
    fn catches_password_env_double_quotes() {
        let s = r#"password="mysuperpassword123""#;
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:password]"), "password not masked: {}", masked);
    }

    #[test]
    fn catches_openrouter_key() {
        let key = format!("sk-or-v1-{}", "a".repeat(64));
        let s = format!("Key: {}", key);
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "OpenRouter key not masked: {}", masked);
    }

    #[test]
    fn catches_stripe_live_key() {
        let s = format!("{}{}", "sk_live_", "abcdefghijklmnopqrstuvwx");
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "Stripe key not masked: {}", masked);
    }

    #[test]
    fn catches_perplexity_key() {
        let key = format!("pplx-{}", "a".repeat(40));
        let masked = mask_text_no_block(&key);
        assert!(masked.contains("[masked:api_key]"), "Perplexity key not masked: {}", masked);
    }

    #[test]
    fn catches_google_firebase_key() {
        let key = format!("AIza{}", "A".repeat(35));
        let masked = mask_text_no_block(&key);
        assert!(masked.contains("[masked:api_key]"), "Firebase key not masked: {}", masked);
    }

    // ===== MULTI-PATTERN TESTS =====

    #[test]
    fn masks_multiple_types_in_one_text() {
        let s = "Email admin@corp.com, call +11234567890, server at 10.0.0.1";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:email]"), "email missed: {}", masked);
        assert!(masked.contains("[masked:phone]"), "phone missed: {}", masked);
        assert!(masked.contains("[masked:ip]"), "ip missed: {}", masked);
    }

    #[test]
    fn masks_key_and_email_together() {
        let s = "Key AKIAIOSFODNN7EXAMPLE sent to user@test.com";
        let masked = mask_text_no_block(&s);
        assert!(masked.contains("[masked:api_key]"), "key missed: {}", masked);
        assert!(masked.contains("[masked:email]"), "email missed: {}", masked);
    }

    // ===== REGEXSET CONSISTENCY TEST =====

    #[test]
    fn regexset_matches_agree_with_individual() {
        let test_cases = vec![
            "Hello world, no sensitive data",
            "Email: test@example.com",
            "AKIAIOSFODNN7EXAMPLE",
            "192.168.1.1",
            "aa:bb:cc:dd:ee:ff",
            "SSN: 123-45-6789",
            r#"SECRET_KEY = "abcdefghij1234567890""#,
        ];

        let set = rule_set();
        let rules = compiled_rules();

        for text in &test_cases {
            let set_matches = set.matches(text);
            for (i, rule) in rules.iter().enumerate() {
                let individual = rule.regex.is_match(text);
                let from_set = set_matches.matched(i);
                assert_eq!(
                    individual, from_set,
                    "Pattern {} ('{}') disagrees: regex={}, set={} on text: {}",
                    i, rule.mask_type, individual, from_set, text
                );
            }
        }
    }

    // ===== EMPTY / EDGE CASES =====

    #[test]
    fn handles_empty_string() {
        assert_eq!(mask_text(""), "");
    }

    #[test]
    fn handles_whitespace_only() {
        let s = "   \n\t  ";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn handles_unicode_text() {
        let s = "Привет мир! Это обычный текст на русском.";
        assert_eq!(mask_text(s), s);
    }

    #[test]
    fn masked_output_never_contains_original_sensitive_data() {
        let sk_key = format!("{}{}", "sk-ant-api03-", "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def123ghi456jkl789mno012pqr345stu678");
        let secrets = vec![
            sk_key.as_str(),
            "user@example.com",
            "+79991234567",
            "123-45-6789",
            "192.168.1.100",
            "aa:bb:cc:dd:ee:ff",
        ];
        let text = secrets.join(" | ");
        let masked = mask_text_no_block(&text);
        for secret in &secrets {
            assert!(
                !masked.contains(secret),
                "Secret '{}' leaked! Result: {}",
                secret, masked
            );
        }
    }
}
