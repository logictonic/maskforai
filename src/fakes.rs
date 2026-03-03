//! Format-matching fake value generation.
//!
//! Generates plausible fake values that match the format of the original
//! sensitive data, so the LLM sees realistic-looking data instead of
//! `[masked:...]` tokens or `[[EMAIL_1]]` placeholders.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Generate a deterministic seed from an original value.
/// Same original always produces the same fake within a session.
fn seed_from(original: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    original.hash(&mut hasher);
    hasher.finish()
}

/// Generate a fake email matching the format of the original.
pub fn fake_email(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));
    let parts: Vec<&str> = original.split('@').collect();
    if parts.len() != 2 {
        return format!("user{}@example.com", rng.gen_range(100..999));
    }
    let local_len = parts[0].len().max(3);
    let domain_parts: Vec<&str> = parts[1].split('.').collect();

    let local: String = (0..local_len)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();

    let domain: String = if domain_parts.len() >= 2 {
        let name_len = domain_parts[0].len().max(3);
        let name: String = (0..name_len)
            .map(|_| {
                let chars = b"abcdefghijklmnopqrstuvwxyz";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect();
        let tld = domain_parts.last().unwrap_or(&"com");
        format!("{}.{}", name, tld)
    } else {
        "example.com".to_string()
    };

    format!("{}@{}", local, domain)
}

/// Generate a fake phone number matching the format of the original.
pub fn fake_phone(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));
    let has_plus = original.starts_with('+');
    let digits: Vec<char> = original.chars().filter(|c| c.is_ascii_digit()).collect();
    let len = digits.len();

    let mut result = String::new();
    if has_plus {
        result.push('+');
        // Keep country code (first 1-3 digits)
        let cc_len = if len > 10 { (len - 10).min(3) } else { 1 };
        for d in digits.iter().take(cc_len) {
            result.push(*d);
        }
        // Generate rest
        for _ in cc_len..len {
            result.push(char::from(b'0' + rng.gen_range(0..10)));
        }
    } else {
        for _ in 0..len {
            result.push(char::from(b'0' + rng.gen_range(0..10)));
        }
    }
    result
}

/// Generate a fake credit card number that passes Luhn validation.
pub fn fake_card(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));
    let digits_only: Vec<u8> = original
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect();
    let len = digits_only.len().max(16);

    // Keep BIN prefix (first 4 digits)
    let mut card: Vec<u8> = Vec::with_capacity(len);
    for d in digits_only.iter().take(4.min(len)) {
        card.push(*d);
    }
    // Generate middle digits
    while card.len() < len - 1 {
        card.push(rng.gen_range(0..10));
    }
    // Calculate Luhn check digit
    let check = luhn_check_digit(&card);
    card.push(check);

    // Reconstruct with original spacing
    let mut result = String::new();
    let mut di = 0;
    for ch in original.chars() {
        if ch.is_ascii_digit() {
            if di < card.len() {
                result.push(char::from(b'0' + card[di]));
                di += 1;
            }
        } else {
            result.push(ch);
        }
    }
    // Append remaining
    while di < card.len() {
        result.push(char::from(b'0' + card[di]));
        di += 1;
    }
    result
}

fn luhn_check_digit(partial: &[u8]) -> u8 {
    let mut sum = 0u32;
    let mut double = true;
    for &d in partial.iter().rev() {
        let mut val = d as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Generate a fake IP address in private range.
pub fn fake_ip(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));
    format!(
        "10.{}.{}.{}",
        rng.gen_range(1..255),
        rng.gen_range(1..255),
        rng.gen_range(1..254)
    )
}

/// Generate a fake SSN with valid format.
pub fn fake_ssn(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));
    let area = rng.gen_range(1..665);
    let group = rng.gen_range(1..100);
    let serial = rng.gen_range(1..10000);
    format!("{:03}-{:02}-{:04}", area, group, serial)
}

/// Generate a fake MAC address.
pub fn fake_mac(_original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(_original));
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        rng.gen_range(0..256),
        rng.gen_range(0..256),
        rng.gen_range(0..256),
        rng.gen_range(0..256),
        rng.gen_range(0..256),
        rng.gen_range(0..256)
    )
}

/// Generate a fake API key preserving prefix and length.
pub fn fake_api_key(original: &str) -> String {
    let mut rng = StdRng::seed_from_u64(seed_from(original));

    let prefix_len = detect_prefix_len(original);
    let prefix = &original[..prefix_len];
    let suffix_len = original.len() - prefix_len;

    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let fake_suffix: String = (0..suffix_len)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();

    format!("{}{}", prefix, fake_suffix)
}

fn detect_prefix_len(key: &str) -> usize {
    // Common prefix patterns
    let prefixes = [
        "sk-ant-admin", "sk-ant-api03-", "sk-ant-",
        "sk-proj-", "sk-or-v1-", "sk-",
        "sk_live_", "sk_test_", "rk_live_",
        "xox", "npm_", "dop_v1_",
        "pplx-", "hf_", "r8_",
        "AIza", "AKIA", "LTAI", "AQVN",
        "sq0", "shpat_", "shpca_", "shppa_",
        "lin_api_", "ntn_", "dp.pt.",
        "pnu_", "ops_", "pul-",
        "sntrys_", "glc_", "glsa_",
        "NRII-", "NRAK-",
        "key-", "SG.", "hvs.CAES",
        "Bearer ",
        "glpat-", "gldt-", "glrt-", "glptt-",
        "gho_", "ghr_",
    ];

    for p in &prefixes {
        if key.starts_with(p) {
            return p.len();
        }
    }

    // Fallback: find first separator char after at least 2 chars
    for (i, ch) in key.char_indices() {
        if i >= 2 && (ch == '-' || ch == '_' || ch == '.') {
            return i + 1;
        }
    }

    key.len().min(4)
}

/// Generate a fake value based on the detected mask type.
pub fn generate_fake(original: &str, mask_type: &str) -> String {
    match mask_type {
        "email" => fake_email(original),
        "phone" => fake_phone(original),
        "card" => fake_card(original),
        "ip" => fake_ip(original),
        "ssn" => fake_ssn(original),
        "mac" => fake_mac(original),
        "api_key" | "bearer" | "jwt" | "webhook" | "generic_secret" => fake_api_key(original),
        "private_key" => "[REDACTED_KEY]".to_string(),
        "db_connection" | "env_var" | "password" | "high_entropy" => {
            let mut rng = StdRng::seed_from_u64(seed_from(original));
            let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
            let len = original.len().min(32).max(8);
            let fake: String = (0..len)
                .map(|_| charset[rng.gen_range(0..charset.len())] as char)
                .collect();
            format!("[fake:{}]", fake)
        }
        _ => fake_api_key(original),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_email_preserves_format() {
        let fake = fake_email("user@company.com");
        assert!(fake.contains('@'), "Missing @: {}", fake);
        assert!(fake.contains('.'), "Missing dot: {}", fake);
        assert_ne!(fake, "user@company.com");
    }

    #[test]
    fn fake_email_deterministic() {
        let a = fake_email("test@example.com");
        let b = fake_email("test@example.com");
        assert_eq!(a, b, "Same input should produce same fake");
    }

    #[test]
    fn fake_email_different_inputs_different_outputs() {
        let a = fake_email("alice@example.com");
        let b = fake_email("bob@example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn fake_phone_preserves_plus_and_country_code() {
        let fake = fake_phone("+79161234567");
        assert!(fake.starts_with("+7"), "Should keep +7: {}", fake);
        assert_eq!(fake.len(), "+79161234567".len());
    }

    #[test]
    fn fake_card_passes_luhn() {
        let fake = fake_card("4111 1111 1111 1111");
        let digits: Vec<u32> = fake
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|c| c.to_digit(10).unwrap())
            .collect();
        let mut sum = 0u32;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut val = d;
            if double {
                val *= 2;
                if val > 9 { val -= 9; }
            }
            sum += val;
            double = !double;
        }
        assert_eq!(sum % 10, 0, "Fake card {} fails Luhn", fake);
    }

    #[test]
    fn fake_card_preserves_spacing() {
        let fake = fake_card("4111 1111 1111 1111");
        let spaces: Vec<usize> = fake.match_indices(' ').map(|(i, _)| i).collect();
        assert_eq!(spaces.len(), 3, "Should have 3 spaces: {}", fake);
    }

    #[test]
    fn fake_ip_is_private_range() {
        let fake = fake_ip("192.168.1.100");
        assert!(fake.starts_with("10."), "Should be in 10.x.x.x: {}", fake);
    }

    #[test]
    fn fake_ssn_valid_format() {
        let fake = fake_ssn("123-45-6789");
        let parts: Vec<&str> = fake.split('-').collect();
        assert_eq!(parts.len(), 3, "Bad format: {}", fake);
        let area: u32 = parts[0].parse().unwrap();
        assert!(area > 0 && area < 666, "Invalid area {}: {}", area, fake);
    }

    #[test]
    fn fake_api_key_preserves_prefix_and_length() {
        let original = "sk-ant-api03-test123456789";
        let fake = fake_api_key(original);
        assert!(fake.starts_with("sk-ant-"), "Should keep prefix: {}", fake);
        assert_eq!(fake.len(), original.len(), "Should keep length: {}", fake);
    }

    #[test]
    fn fake_api_key_deterministic() {
        let a = fake_api_key("sk-ant-api03-test123");
        let b = fake_api_key("sk-ant-api03-test123");
        assert_eq!(a, b);
    }

    #[test]
    fn generate_fake_dispatches_correctly() {
        let email = generate_fake("user@test.com", "email");
        assert!(email.contains('@'));

        let phone = generate_fake("+1234567890", "phone");
        assert!(phone.starts_with('+'));

        let ip = generate_fake("192.168.1.1", "ip");
        assert!(ip.starts_with("10."));
    }
}
