//! Difficulty estimates for vanity patterns.

use erg_vanity_cpu::MatchType;

/// Estimated effort for a pattern.
#[derive(Debug, Clone)]
pub struct PatternEstimate {
    pub attempts_needed: f64,
    pub has_invalid_chars: bool,
    pub invalid_chars: Vec<char>,
}

/// Estimate attempts for a Base58 pattern at the given match type.
pub fn estimate_pattern(pattern: &str, match_type: MatchType) -> PatternEstimate {
    let mut invalid_chars = Vec::new();
    for c in pattern.chars() {
        if !is_base58_char(c) && !invalid_chars.contains(&c) {
            invalid_chars.push(c);
        }
    }
    if !invalid_chars.is_empty() {
        return PatternEstimate {
            attempts_needed: f64::INFINITY,
            has_invalid_chars: true,
            invalid_chars,
        };
    }

    let n = pattern.len() as f64;
    let attempts = match match_type {
        MatchType::Prefix => {
            if n <= 1.0 {
                1.0
            } else {
                // After leading '9', second char is one of 5, then 58 each
                5.0 * 58.0f64.powf((n - 2.0).max(0.0))
            }
        }
        MatchType::Suffix | MatchType::Contains => {
            let avg_len = 51.0;
            let positions = (avg_len - n + 1.0).max(1.0);
            58.0f64.powf(n) / positions
        }
    };

    PatternEstimate {
        attempts_needed: attempts * 1.2,
        has_invalid_chars: false,
        invalid_chars: Vec::new(),
    }
}

/// Format seconds as a short human string.
pub fn format_time(seconds: f64) -> String {
    if seconds.is_infinite() {
        "impossible".to_string()
    } else if seconds < 1.0 {
        "less than a second".to_string()
    } else if seconds < 60.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else {
        format!("{:.1} days", seconds / 86400.0)
    }
}

fn is_base58_char(c: char) -> bool {
    matches!(c,
        '1'..='9' |
        'A'..='H' | 'J'..='N' | 'P'..='Z' |
        'a'..='k' | 'm'..='z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_longer_is_harder() {
        let a = estimate_pattern("9e", MatchType::Prefix);
        let b = estimate_pattern("9ergo", MatchType::Prefix);
        assert!(b.attempts_needed > a.attempts_needed);
    }

    #[test]
    fn invalid_chars_are_impossible() {
        let e = estimate_pattern("9eO", MatchType::Prefix);
        assert!(e.has_invalid_chars);
        assert!(e.attempts_needed.is_infinite());
    }
}
