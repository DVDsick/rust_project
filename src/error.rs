/// Custom error types for the Telegram password bot.
use thiserror::Error;

/// Main error type for the application.
#[derive(Error, Debug)]
pub enum BotError {
    /// Configuration errors (missing or invalid environment variables).
    #[error("Configuration error: {0}")]
    Config(String),

    /// Password generation errors (invalid parameters).
    #[error("Password generation error: {0}")]
    PasswordGeneration(String),

    /// Rate limiting errors.
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Telegram API errors.
    #[error("Telegram error: {0}")]
    Telegram(#[from] teloxide::RequestError),

    /// Generic I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Environment variable parsing errors.
    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),

    /// Integer parsing errors.
    #[error("Parse error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

/// Convenient Result alias using our custom error type.
pub type Result<T> = std::result::Result<T, BotError>;
