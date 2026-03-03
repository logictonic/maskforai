//! Shannon entropy-based secret detection.
//!
//! Detects high-entropy strings that are likely secrets (API keys,
//! passwords, cryptographic material) even without matching any
//! specific regex pattern.

/// Calculate Shannon entropy of a byte slice.
/// Returns a value between 0.0 (completely uniform) and 8.0 (maximum randomness).
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f32 / len;
            -p * p.log2()
        })
        .sum()
}

/// Minimum token length to consider for entropy detection.
const MIN_TOKEN_LEN: usize = 20;

/// Default entropy threshold. Strings with entropy >= this are flagged.
/// Normal text: ~3.5-4.5, secrets: ~5.0-6.0, random bytes: ~7.0-8.0.
pub const DEFAULT_ENTROPY_THRESHOLD: f32 = 4.8;

/// Check if a string token looks like a high-entropy secret.
fn is_high_entropy(token: &str, threshold: f32) -> bool {
    if token.len() < MIN_TOKEN_LEN {
        return false;
    }
    // Skip tokens that are clearly not secrets
    if token.chars().all(|c| c.is_ascii_lowercase() || c == ' ') {
        return false; // plain english words
    }
    if token.chars().all(|c| c.is_ascii_digit()) {
        return false; // pure numbers
    }
    shannon_entropy(token.as_bytes()) >= threshold
}

/// Scan text for high-entropy tokens and mask them.
/// Tokens are split by whitespace, `=`, `:`, `"`, `'`, and common delimiters.
pub fn mask_high_entropy(text: &str, threshold: f32) -> (String, u32) {
    let mut result = text.to_string();
    let mut count = 0u32;

    // Find potential secret tokens: sequences of printable non-whitespace chars
    let mut i = 0;
    let bytes = text.as_bytes();
    let mut replacements: Vec<(usize, usize)> = Vec::new();

    while i < bytes.len() {
        // Skip whitespace and common delimiters
        if bytes[i].is_ascii_whitespace() || matches!(bytes[i], b'=' | b':' | b'"' | b'\'' | b',' | b';' | b'(' | b')' | b'{' | b'}' | b'[' | b']') {
            i += 1;
            continue;
        }

        // Collect token
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b':' | b'"' | b'\'' | b',' | b';' | b'(' | b')' | b'{' | b'}' | b'[' | b']') {
            i += 1;
        }
        let token = &text[start..i];

        if is_high_entropy(token, threshold) {
            replacements.push((start, i));
            count += 1;
        }
    }

    // Apply replacements in reverse order
    for (start, end) in replacements.into_iter().rev() {
        result.replace_range(start..end, "[masked:high_entropy]****");
    }

    (result, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_normal_text() {
        let e = shannon_entropy(b"hello world this is normal text");
        assert!(e < 4.0, "Normal text entropy too high: {}", e);
    }

    #[test]
    fn high_entropy_random_string() {
        let e = shannon_entropy(b"aB3$kL9@mN2#pQ5&rT8*vX1!yZ4%cF7^");
        assert!(e > 4.5, "Random string entropy too low: {}", e);
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_single_byte() {
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn mask_high_entropy_detects_secret() {
        let text = "config KEY=aB3kL9mN2pQ5rT8vX1yZ4cF7hJ0wE6";
        let (masked, count) = mask_high_entropy(text, DEFAULT_ENTROPY_THRESHOLD);
        assert!(count > 0, "Should detect high entropy token");
        assert!(masked.contains("[masked:high_entropy]"), "got: {}", masked);
    }

    #[test]
    fn mask_high_entropy_ignores_normal_text() {
        let text = "This is a completely normal sentence with no secrets at all";
        let (masked, count) = mask_high_entropy(text, DEFAULT_ENTROPY_THRESHOLD);
        assert_eq!(count, 0, "Should not detect normal text");
        assert_eq!(masked, text);
    }

    #[test]
    fn mask_high_entropy_ignores_short_tokens() {
        let text = "short aB3k normal";
        let (masked, count) = mask_high_entropy(text, DEFAULT_ENTROPY_THRESHOLD);
        assert_eq!(count, 0);
        assert_eq!(masked, text);
    }
}
