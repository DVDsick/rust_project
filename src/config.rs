/// Configuration management for the Telegram password bot.
use crate::error::{BotError, Result};
use std::env;

/// Main application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Telegram bot token (from TELEGRAM_BOT_TOKEN).
    pub bot_token: String,
    /// Default password length if user doesn't specify.
    pub default_password_length: usize,
    /// Maximum allowed password length.
    pub max_password_length: usize,
    /// Minimum allowed password length.
    pub min_password_length: usize,
    /// Maximum password generation requests per chat per minute.
    pub rate_limit_per_minute: usize,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required environment variables:
    /// - `TELEGRAM_BOT_TOKEN`: The bot token from BotFather.
    ///
    /// Optional environment variables:
    /// - `DEFAULT_PASSWORD_LENGTH`: Default password length (default: 16).
    /// - `MAX_PASSWORD_LENGTH`: Maximum password length (default: 64).
    /// - `MIN_PASSWORD_LENGTH`: Minimum password length (default: 8).
    /// - `RATE_LIMIT_PER_MINUTE`: Max requests per chat per minute (default: 10).
    pub fn from_env() -> Result<Self> {
        // Required: bot token
        let bot_token = env::var("TELEGRAM_BOT_TOKEN").map_err(|_| {
            BotError::Config(
                "TELEGRAM_BOT_TOKEN environment variable is required. \
                 Get your token from @BotFather on Telegram."
                    .to_string(),
            )
        })?;

        if bot_token.is_empty() {
            return Err(BotError::Config(
                "TELEGRAM_BOT_TOKEN cannot be empty".to_string(),
            ));
        }

        // Optional: default password length
        let default_password_length = env::var("DEFAULT_PASSWORD_LENGTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16);

        // Optional: max password length
        let max_password_length = env::var("MAX_PASSWORD_LENGTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(64);

        // Optional: min password length
        let min_password_length = env::var("MIN_PASSWORD_LENGTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(8);

        // Optional: rate limit
        let rate_limit_per_minute = env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(10);

        // Validate configuration
        if min_password_length == 0 {
            return Err(BotError::Config(
                "MIN_PASSWORD_LENGTH must be greater than 0".to_string(),
            ));
        }

        if max_password_length < min_password_length {
            return Err(BotError::Config(format!(
                "MAX_PASSWORD_LENGTH ({}) must be >= MIN_PASSWORD_LENGTH ({})",
                max_password_length, min_password_length
            )));
        }

        if default_password_length < min_password_length
            || default_password_length > max_password_length
        {
            return Err(BotError::Config(format!(
                "DEFAULT_PASSWORD_LENGTH ({}) must be between {} and {}",
                default_password_length, min_password_length, max_password_length
            )));
        }

        Ok(Config {
            bot_token,
            default_password_length,
            max_password_length,
            min_password_length,
            rate_limit_per_minute,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        // Test that default values are sensible
        let config = Config {
            bot_token: "test_token".to_string(),
            default_password_length: 16,
            max_password_length: 64,
            min_password_length: 8,
            rate_limit_per_minute: 10,
        };

        assert!(config.default_password_length >= config.min_password_length);
        assert!(config.default_password_length <= config.max_password_length);
        assert!(config.max_password_length >= config.min_password_length);
    }
}
