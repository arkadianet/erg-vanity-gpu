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
    pattern: String,
    match_type: MatchType,
    ignore_case: bool,
}

impl Pattern {
    /// Create a new prefix matcher.
    pub fn prefix(pattern: impl Into<String>) -> Self {
        Self::new(pattern, MatchType::Prefix)
    }

    /// Create a new suffix matcher.
    pub fn suffix(pattern: impl Into<String>) -> Self {
        Self::new(pattern, MatchType::Suffix)
    }

    /// Create a new contains matcher.
    pub fn contains(pattern: impl Into<String>) -> Self {
        Self::new(pattern, MatchType::Contains)
    }

    /// Create a matcher with explicit match type.
    pub fn new(pattern: impl Into<String>, match_type: MatchType) -> Self {
        Self {
            pattern: pattern.into(),
            match_type,
            ignore_case: false,
        }
    }

    /// Enable ASCII case-insensitive matching.
    pub fn ignore_case(mut self, ignore: bool) -> Self {
        self.ignore_case = ignore;
        self
    }

    /// Check if the address matches the pattern.
    pub fn matches(&self, address: &str) -> bool {
        if self.ignore_case {
            let addr = address.to_ascii_lowercase();
            let pat = self.pattern.to_ascii_lowercase();
            return match self.match_type {
                MatchType::Prefix => addr.starts_with(&pat),
                MatchType::Suffix => addr.ends_with(&pat),
                MatchType::Contains => addr.contains(&pat),
            };
        }
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

/// Index of the longest matching pattern, ties broken by list order.
pub fn first_match(patterns: &[Pattern], address: &str) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (i, p) in patterns.iter().enumerate() {
        if !p.matches(address) {
            continue;
        }
        let len = p.len();
        match best {
            None => best = Some((len, i)),
            Some((best_len, _)) if len > best_len => best = Some((len, i)),
            Some((best_len, best_i)) if len == best_len && i < best_i => best = Some((len, i)),
            _ => {}
        }
    }
    best.map(|(_, i)| i)
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
    fn test_ignore_case() {
        let pattern = Pattern::prefix("ABC").ignore_case(true);
        assert!(pattern.matches("abcdef"));
        assert!(pattern.matches("ABCdef"));
    }

    #[test]
    fn test_first_match_longest_wins() {
        let patterns = vec![
            Pattern::prefix("9e"),
            Pattern::prefix("9ergo"),
            Pattern::prefix("9er"),
        ];
        assert_eq!(first_match(&patterns, "9ergoXXXX"), Some(1));
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
        assert!(Pattern::prefix("0abc").validate().is_err());
        assert!(Pattern::prefix("Oops").validate().is_err());
        assert!(Pattern::prefix("Invalid").validate().is_err());
        assert!(Pattern::prefix("lol").validate().is_err());
    }
}
