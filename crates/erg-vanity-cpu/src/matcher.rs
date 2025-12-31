//! Pattern matching for vanity addresses.

#![forbid(unsafe_code)]

/// Match type for vanity patterns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    /// Pattern must appear at the start of the address
    Prefix,
    /// Pattern must appear at the end of the address
    Suffix,
    /// Pattern must appear anywhere in the address
    Contains,
}

/// A compiled vanity pattern matcher.
#[derive(Clone, Debug)]
pub struct Pattern {
    /// The pattern to match (case-sensitive)
    pattern: String,
    /// The match type
    match_type: MatchType,
}

impl Pattern {
    /// Create a new prefix matcher.
    pub fn prefix(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            match_type: MatchType::Prefix,
        }
    }

    /// Create a new suffix matcher.
    pub fn suffix(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            match_type: MatchType::Suffix,
        }
    }

    /// Create a new contains matcher.
    pub fn contains(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            match_type: MatchType::Contains,
        }
    }

    /// Create a matcher with explicit match type.
    pub fn new(pattern: impl Into<String>, match_type: MatchType) -> Self {
        Self {
            pattern: pattern.into(),
            match_type,
        }
    }

    /// Check if the address matches the pattern.
    pub fn matches(&self, address: &str) -> bool {
        match self.match_type {
            MatchType::Prefix => address.starts_with(&self.pattern),
            MatchType::Suffix => address.ends_with(&self.pattern),
            MatchType::Contains => address.contains(&self.pattern),
        }
    }

    /// Get the pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Get the match type.
    pub fn match_type(&self) -> MatchType {
        self.match_type
    }

    /// Get the pattern length (useful for difficulty estimation).
    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    /// Check if the pattern is empty.
    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }

    /// Validate that the pattern contains only Base58 characters.
    ///
    /// Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    /// Excludes: 0, O, I, l (and any non-alphanumeric)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pattern.is_empty() {
            return Err("pattern is empty");
        }

        for c in self.pattern.chars() {
            if !is_base58_char(c) {
                return Err("pattern contains invalid Base58 character");
            }
        }

        Ok(())
    }
}

/// Check if a character is in the Base58 alphabet.
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
    fn test_prefix_match() {
        let pattern = Pattern::prefix("9abc");
        assert!(pattern.matches("9abcdefghijk"));
        assert!(!pattern.matches("9xyz"));
        assert!(!pattern.matches("abc9"));
    }

    #[test]
    fn test_suffix_match() {
        let pattern = Pattern::suffix("xyz");
        assert!(pattern.matches("9abcdefxyz"));
        assert!(!pattern.matches("xyz9abc"));
        assert!(!pattern.matches("9abc"));
    }

    #[test]
    fn test_contains_match() {
        let pattern = Pattern::contains("def");
        assert!(pattern.matches("abcdefghi"));
        assert!(pattern.matches("defghi"));
        assert!(pattern.matches("abcdef"));
        assert!(!pattern.matches("abc"));
    }

    #[test]
    fn test_case_sensitive() {
        let pattern = Pattern::prefix("ABC");
        assert!(pattern.matches("ABCdef"));
        assert!(!pattern.matches("abcdef"));
    }

    #[test]
    fn test_empty_pattern() {
        let pattern = Pattern::prefix("");
        assert!(pattern.matches("anything"));
        assert!(pattern.is_empty());
    }

    #[test]
    fn test_validate_valid_pattern() {
        assert!(Pattern::prefix("9abc").validate().is_ok());
        assert!(Pattern::prefix("ABC123xyz").validate().is_ok());
    }

    #[test]
    fn test_validate_empty_rejected() {
        assert!(Pattern::prefix("").validate().is_err());
    }

    #[test]
    fn test_validate_invalid_chars_rejected() {
        // 0, O, I, l are not in Base58
        assert!(Pattern::prefix("0abc").validate().is_err());
        assert!(Pattern::prefix("Oops").validate().is_err());
        assert!(Pattern::prefix("Invalid").validate().is_err());
        assert!(Pattern::prefix("lol").validate().is_err());
    }
}
