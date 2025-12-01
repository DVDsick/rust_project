/// Password generation and strength estimation.
///
/// This module provides cryptographically secure password generation using
/// OS-level randomness (OsRng) and basic password strength estimation.
use crate::error::{BotError, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_core::RngCore;

/// Configuration for password generation.
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Length of the password to generate.
    pub length: usize,
    /// Include lowercase letters (a-z).
    pub use_lowercase: bool,
    /// Include uppercase letters (A-Z).
    pub use_uppercase: bool,
    /// Include digits (0-9).
    pub use_digits: bool,
    /// Include symbols (!@#$%^&*...).
    pub use_symbols: bool,
    /// Exclude ambiguous characters (0, O, o, 1, l, I).
    pub exclude_ambiguous: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordConfig {
    /// Validate that the configuration is sensible.
    pub fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(BotError::PasswordGeneration(
                "Password length must be greater than 0".to_string(),
            ));
        }

        if !self.use_lowercase
            && !self.use_uppercase
            && !self.use_digits
            && !self.use_symbols
        {
            return Err(BotError::PasswordGeneration(
                "At least one character type must be enabled".to_string(),
            ));
        }

        Ok(())
    }

    /// Build the character pool based on enabled options.
    pub fn build_char_pool(&self) -> Vec<char> {
        let mut pool = Vec::new();

        // Define character sets
        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = "0123456789";
        let symbols = "!@#$%^&*()-_=+[]{};:,.?/";

        // Ambiguous characters to exclude if requested
        let ambiguous = ['0', 'O', 'o', '1', 'l', 'I'];

        if self.use_lowercase {
            pool.extend(lowercase.chars().filter(|c| {
                !self.exclude_ambiguous || !ambiguous.contains(c)
            }));
        }

        if self.use_uppercase {
            pool.extend(uppercase.chars().filter(|c| {
                !self.exclude_ambiguous || !ambiguous.contains(c)
            }));
        }

        if self.use_digits {
            pool.extend(digits.chars().filter(|c| {
                !self.exclude_ambiguous || !ambiguous.contains(c)
            }));
        }

        if self.use_symbols {
            pool.extend(symbols.chars());
        }

        pool
    }

    /// Get the list of required character groups (at least one from each enabled).
    fn required_chars(&self) -> Vec<Vec<char>> {
        let mut required = Vec::new();

        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = "0123456789";
        let symbols = "!@#$%^&*()-_=+[]{};:,.?/";
        let ambiguous = ['0', 'O', 'o', '1', 'l', 'I'];

        if self.use_lowercase {
            let chars: Vec<char> = lowercase
                .chars()
                .filter(|c| !self.exclude_ambiguous || !ambiguous.contains(c))
                .collect();
            if !chars.is_empty() {
                required.push(chars);
            }
        }

        if self.use_uppercase {
            let chars: Vec<char> = uppercase
                .chars()
                .filter(|c| !self.exclude_ambiguous || !ambiguous.contains(c))
                .collect();
            if !chars.is_empty() {
                required.push(chars);
            }
        }

        if self.use_digits {
            let chars: Vec<char> = digits
                .chars()
                .filter(|c| !self.exclude_ambiguous || !ambiguous.contains(c))
                .collect();
            if !chars.is_empty() {
                required.push(chars);
            }
        }

        if self.use_symbols {
            required.push(symbols.chars().collect());
        }

        required
    }
}

/// Generate a cryptographically secure random password.
///
/// # Arguments
/// * `config` - Password configuration specifying length and character types.
/// * `rng` - A cryptographically secure random number generator (e.g., OsRng).
///
/// # Returns
/// A randomly generated password string.
///
/// # Security
/// This function uses the provided RNG to select characters uniformly at random
/// from the allowed character pool. It ensures at least one character from each
/// enabled category appears in the password.
pub fn generate_password(config: &PasswordConfig, rng: &mut impl RngCore) -> Result<String> {
    config.validate()?;

    let char_pool = config.build_char_pool();
    if char_pool.is_empty() {
        return Err(BotError::PasswordGeneration(
            "Character pool is empty".to_string(),
        ));
    }

    let required_groups = config.required_chars();
    let required_count = required_groups.len();

    if config.length < required_count {
        return Err(BotError::PasswordGeneration(format!(
            "Password length ({}) is too short for the required character types ({})",
            config.length, required_count
        )));
    }

    let mut password_chars = Vec::with_capacity(config.length);

    // First, ensure at least one character from each required group
    for group in &required_groups {
        let idx = rng.gen_range(0..group.len());
        password_chars.push(group[idx]);
    }

    // Fill the rest with random characters from the full pool
    for _ in required_count..config.length {
        let idx = rng.gen_range(0..char_pool.len());
        password_chars.push(char_pool[idx]);
    }

    // Shuffle to avoid predictable patterns (required chars at the start)
    password_chars.shuffle(rng);

    Ok(password_chars.into_iter().collect())
}

/// Password strength category based on entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    Weak,
    Medium,
    Strong,
}

impl PasswordStrength {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Medium => "Medium",
            PasswordStrength::Strong => "Strong",
        }
    }
}

/// Estimate password strength based on entropy.
///
/// Entropy is calculated as: length × log2(pool_size).
///
/// Strength categories:
/// - Weak: < 50 bits
/// - Medium: 50-80 bits
/// - Strong: >= 80 bits
pub fn estimate_strength(config: &PasswordConfig) -> PasswordStrength {
    let pool_size = config.build_char_pool().len();
    if pool_size == 0 {
        return PasswordStrength::Weak;
    }

    // Calculate entropy in bits
    let entropy = (config.length as f64) * (pool_size as f64).log2();

    if entropy < 50.0 {
        PasswordStrength::Weak
    } else if entropy < 80.0 {
        PasswordStrength::Medium
    } else {
        PasswordStrength::Strong
    }
}

/// Format password metadata for display (without revealing the password in logs).
pub fn format_metadata(config: &PasswordConfig, strength: PasswordStrength) -> String {
    let pool_size = config.build_char_pool().len();
    let entropy = (config.length as f64) * (pool_size as f64).log2();

    let mut char_types = Vec::new();
    if config.use_lowercase {
        char_types.push("lowercase");
    }
    if config.use_uppercase {
        char_types.push("uppercase");
    }
    if config.use_digits {
        char_types.push("digits");
    }
    if config.use_symbols {
        char_types.push("symbols");
    }

    format!(
        "Length: {} | Types: {} | Pool size: {} | Entropy: {:.1} bits | Strength: {}",
        config.length,
        char_types.join(", "),
        pool_size,
        entropy,
        strength.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_default_config() {
        let config = PasswordConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.length > 0);
        assert!(config.use_lowercase || config.use_uppercase || config.use_digits || config.use_symbols);
    }

    #[test]
    fn test_password_length() {
        let config = PasswordConfig {
            length: 20,
            ..Default::default()
        };
        let mut rng = OsRng;
        let password = generate_password(&config, &mut rng).unwrap();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_password_contains_required_types() {
        let config = PasswordConfig {
            length: 16,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: false,
            exclude_ambiguous: false,
        };
        let mut rng = OsRng;
        let password = generate_password(&config, &mut rng).unwrap();

        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());

        assert!(has_lowercase, "Password should contain lowercase");
        assert!(has_uppercase, "Password should contain uppercase");
        assert!(has_digit, "Password should contain digit");
    }

    #[test]
    fn test_no_ambiguous_characters() {
        let config = PasswordConfig {
            length: 20,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: false,
            exclude_ambiguous: true,
        };
        let mut rng = OsRng;
        let password = generate_password(&config, &mut rng).unwrap();

        let ambiguous = ['0', 'O', 'o', '1', 'l', 'I'];
        for c in password.chars() {
            assert!(!ambiguous.contains(&c), "Found ambiguous character: {}", c);
        }
    }

    #[test]
    fn test_invalid_config_no_char_types() {
        let config = PasswordConfig {
            length: 16,
            use_lowercase: false,
            use_uppercase: false,
            use_digits: false,
            use_symbols: false,
            exclude_ambiguous: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_config_zero_length() {
        let config = PasswordConfig {
            length: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_strength_estimation() {
        // Strong password
        let strong_config = PasswordConfig {
            length: 20,
            ..Default::default()
        };
        assert_eq!(estimate_strength(&strong_config), PasswordStrength::Strong);

        // Weak password
        let weak_config = PasswordConfig {
            length: 6,
            use_lowercase: true,
            use_uppercase: false,
            use_digits: false,
            use_symbols: false,
            exclude_ambiguous: false,
        };
        assert_eq!(estimate_strength(&weak_config), PasswordStrength::Weak);
    }

    #[test]
    fn test_char_pool_building() {
        let config = PasswordConfig {
            length: 10,
            use_lowercase: true,
            use_uppercase: false,
            use_digits: true,
            use_symbols: false,
            exclude_ambiguous: false,
        };
        let pool = config.build_char_pool();
        assert!(pool.len() > 0);
        assert!(pool.iter().any(|c| c.is_ascii_lowercase()));
        assert!(pool.iter().any(|c| c.is_ascii_digit()));
        assert!(!pool.iter().any(|c| c.is_ascii_uppercase()));
    }
}
