/// Telegram bot command handlers and message processing.
use crate::config::Config;
use crate::error::{BotError, Result};
use crate::password::{
    estimate_strength, format_metadata, generate_password, PasswordConfig, PasswordStrength,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use teloxide::prelude::*;
use teloxide::types::CallbackQuery;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Rate limiter tracking password generation requests per chat.
#[derive(Debug, Default)]
pub struct RateLimiter {
    /// Map of chat_id to timestamps of recent requests.
    requests: HashMap<i64, Vec<Instant>>,
}

impl RateLimiter {
    /// Check if a request from the given chat is allowed.
    /// Returns Ok(()) if allowed, Err if rate limit exceeded.
    pub fn check_rate_limit(&mut self, chat_id: i64, limit: usize) -> Result<()> {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Get or create the request history for this chat
        let requests = self.requests.entry(chat_id).or_insert_with(Vec::new);

        // Remove requests older than 1 minute
        requests.retain(|&timestamp| timestamp > one_minute_ago);

        // Check if limit is exceeded
        if requests.len() >= limit {
            return Err(BotError::RateLimit(format!(
                "Too many requests. Maximum {} password generations per minute. Please wait.",
                limit
            )));
        }

        // Add the current request
        requests.push(now);
        Ok(())
    }
}

/// Shared bot state including configuration and rate limiter.
#[derive(Clone)]
pub struct BotState {
    pub config: Arc<Config>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl BotState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        }
    }
}

/// Handler for the /start command.
pub async fn handle_start(bot: Bot, msg: Message) -> ResponseResult<()> {
    let welcome_text = "🔐 Secure Password Generator Bot\n\n\
        Welcome! I generate strong, random passwords using cryptographically secure randomness.\n\n\
        🔒 Privacy Notice:\n\
        • Passwords are generated using OS-level secure randomness\n\
        • Passwords are NOT logged or stored on the server\n\
        • However, Telegram messages are not end-to-end encrypted\n\
        • Use this bot as a convenience tool, but be aware of inherent risks\n\n\
        📝 Quick Start:\n\
        Use /pass to generate a password with default settings, or customize it:\n\
        • /pass - Default 16-character password\n\
        • /pass 24 - 24-character password\n\
        • /pass 20 --symbols - Include symbols\n\
        • /pass 16 --no-ambiguous - Exclude ambiguous characters\n\n\
        Type /help for detailed usage information.";

    use teloxide::types::InlineKeyboardButton;
    let keyboard = teloxide::types::InlineKeyboardMarkup::new(vec![
        vec![
            InlineKeyboardButton::callback("📋 Default (16)", "pass_default"),
            InlineKeyboardButton::callback("🔒 Strong (24)", "pass_24"),
        ],
        vec![
            InlineKeyboardButton::callback("📖 Help", "show_help"),
        ],
    ]);

    bot.send_message(msg.chat.id, welcome_text)
        .reply_markup(keyboard)
        .await?;

    info!(
        "User {} started the bot",
        msg.chat.id
    );

    Ok(())
}

/// Handler for the /help command.
pub async fn handle_help(bot: Bot, msg: Message, state: BotState) -> ResponseResult<()> {
    let help_text = format!(
        "🔐 Password Generator - Help\n\n\
        Available Commands:\n\
        • /start - Welcome message\n\
        • /help - Show this help message\n\
        • /pass or /password - Generate a secure password\n\n\
        Password Generation Syntax:\n\
        /pass [length] [options]\n\n\
        Examples:\n\
        • /pass - Default password (length: {})\n\
        • /pass 24 - 24-character password\n\
        • /pass 20 --symbols - Include symbols\n\
        • /pass 16 --no-symbols - No symbols\n\
        • /pass 18 --no-ambiguous - Exclude ambiguous chars (0,O,o,1,l,I)\n\
        • /pass 20 --no-digits --symbols - No digits, with symbols\n\n\
        Available Options:\n\
        • --symbols / --no-symbols\n\
        • --digits / --no-digits\n\
        • --uppercase / --no-uppercase\n\
        • --lowercase / --no-lowercase\n\
        • --no-ambiguous - Exclude confusing characters\n\n\
        Constraints:\n\
        • Min length: {} characters\n\
        • Max length: {} characters\n\
        • At least one character type must be enabled\n\
        • Rate limit: {} passwords per minute per chat\n\n\
        Security Recommendations:\n\
        ✅ Use long passwords (16+ characters)\n\
        ✅ Use unique passwords for each account\n\
        ✅ Store passwords in a secure password manager\n\
        ⚠️ Remember: Telegram is not end-to-end encrypted\n\
        ⚠️ This bot doesn't log passwords, but they travel through Telegram's servers",
        state.config.default_password_length,
        state.config.min_password_length,
        state.config.max_password_length,
        state.config.rate_limit_per_minute
    );

    use teloxide::types::InlineKeyboardButton;
    let keyboard = teloxide::types::InlineKeyboardMarkup::new(vec![
        vec![
            InlineKeyboardButton::callback("📋 Default", "pass_default"),
            InlineKeyboardButton::callback("🔒 Strong (24)", "pass_24"),
        ],
        vec![
            InlineKeyboardButton::callback("🔤 No Symbols", "pass_no_symbols"),
            InlineKeyboardButton::callback("🚫 Ambiguous", "pass_no_ambiguous"),
        ],
        vec![
            InlineKeyboardButton::callback("🔐 Very Strong (32)", "pass_32"),
            InlineKeyboardButton::callback("📏 Custom Length", "pass_custom"),
        ],
    ]);

    bot.send_message(msg.chat.id, help_text)
        .reply_markup(keyboard)
        .await?;

    Ok(())
}

/// Parse password generation command arguments.
///
/// Expected format: /pass [length] [--option1] [--option2] ...
pub fn parse_password_args(args: &str, default_length: usize) -> Result<PasswordConfig> {
    let mut config = PasswordConfig::default();
    config.length = default_length;

    let parts: Vec<&str> = args.split_whitespace().collect();

    for part in parts {
        if part.starts_with("--") {
            // Parse options
            match part {
                "--symbols" => config.use_symbols = true,
                "--no-symbols" => config.use_symbols = false,
                "--digits" => config.use_digits = true,
                "--no-digits" => config.use_digits = false,
                "--uppercase" => config.use_uppercase = true,
                "--no-uppercase" => config.use_uppercase = false,
                "--lowercase" => config.use_lowercase = true,
                "--no-lowercase" => config.use_lowercase = false,
                "--no-ambiguous" => config.exclude_ambiguous = true,
                _ => {
                    return Err(BotError::PasswordGeneration(format!(
                        "Unknown option: {}",
                        part
                    )))
                }
            }
        } else {
            // Try to parse as length
            match part.parse::<usize>() {
                Ok(len) => config.length = len,
                Err(_) => {
                    return Err(BotError::PasswordGeneration(format!(
                        "Invalid length: '{}'. Expected a number.",
                        part
                    )))
                }
            }
        }
    }

    Ok(config)
}

/// Handler for the /pass and /password commands.
pub async fn handle_password(
    bot: Bot,
    msg: Message,
    state: BotState,
    args: String,
) -> ResponseResult<()> {
    let chat_id = msg.chat.id.0;

    // Check rate limit
    {
        let mut rate_limiter = state.rate_limiter.lock().await;
        if let Err(e) = rate_limiter.check_rate_limit(chat_id, state.config.rate_limit_per_minute)
        {
            bot.send_message(msg.chat.id, e.to_string()).await?;
            warn!(
                "Rate limit exceeded for chat {}: {}",
                chat_id, e
            );
            return Ok(());
        }
    }

    // Parse arguments
    let password_config = match parse_password_args(&args, state.config.default_password_length)
    {
        Ok(config) => config,
        Err(e) => {
            let error_msg = format!(
                "❌ Error: {}\n\nUsage: `/pass [length] [options]`\n\
                 Example: `/pass 20 --symbols --no-ambiguous`\n\n\
                 Type `/help` for detailed usage.",
                e
            );
            bot.send_message(msg.chat.id, error_msg)
                .await?;
            return Ok(());
        }
    };

    // Validate length bounds
    if password_config.length < state.config.min_password_length {
        let error_msg = format!(
            "❌ Password length too short. Minimum: {} characters.",
            state.config.min_password_length
        );
        bot.send_message(msg.chat.id, error_msg).await?;
        return Ok(());
    }

    if password_config.length > state.config.max_password_length {
        let error_msg = format!(
            "❌ Password length too long. Maximum: {} characters.",
            state.config.max_password_length
        );
        bot.send_message(msg.chat.id, error_msg).await?;
        return Ok(());
    }

    // Validate configuration
    if let Err(e) = password_config.validate() {
        let error_msg = format!(
            "❌ Configuration error: {}\n\n\
             Make sure at least one character type is enabled.",
            e
        );
        bot.send_message(msg.chat.id, error_msg).await?;
        return Ok(());
    }

    // Generate password using cryptographically secure RNG
    let mut rng = OsRng;
    let password = match generate_password(&password_config, &mut rng) {
        Ok(pwd) => pwd,
        Err(e) => {
            let error_msg = format!("❌ Failed to generate password: {}", e);
            bot.send_message(msg.chat.id, error_msg).await?;
            return Ok(());
        }
    };

    // Estimate strength
    let strength = estimate_strength(&password_config);
    let metadata = format_metadata(&password_config, strength);

    // Format response (send password in monospace for better readability)
    let strength_emoji = match strength {
        PasswordStrength::Strong => "💪",
        PasswordStrength::Medium => "👍",
        PasswordStrength::Weak => "⚠️",
    };

    let response = format!(
        "🔐 Your Secure Password:\n\n`{}`\n\n{} {}\n\n⚠️ Security reminder: Copy this password immediately and store it securely. This message will remain in your chat history.",
        password, strength_emoji, metadata
    );

    bot.send_message(msg.chat.id, response)
        .await?;

    // Log metadata only (never log the actual password)
    info!(
        "Generated password for chat {}: {}",
        chat_id, metadata
    );

    Ok(())
}

/// Handler for inline button callbacks.
pub async fn handle_callback(
    bot: Bot,
    q: CallbackQuery,
    state: BotState,
) -> ResponseResult<()> {
    use teloxide::types::InlineKeyboardButton;
    
    if let Some(ref data) = q.data {
        // Handle different button callbacks
        let message = match data.as_str() {
            "pass_default" => "/pass".to_string(),
            "pass_24" => "/pass 24".to_string(),
            "pass_32" => "/pass 32".to_string(),
            "pass_no_symbols" => "/pass 16 --no-symbols".to_string(),
            "pass_no_ambiguous" => "/pass 18 --no-ambiguous".to_string(),
            "pass_custom" => {
                bot.answer_callback_query(&q.id).await?;
                bot.send_message(
                    q.from.id,
                    "📝 Please type your custom password command:\nExample: /pass 20 --symbols --no-digits",
                )
                .await?;
                return Ok(());
            }
            "show_help" => {
                // Re-send help with buttons
                let help_text = format!(
                    "🔐 Password Generator - Help\n\n\
                    Available Commands:\n\
                    • /start - Welcome message\n\
                    • /help - Show this help message\n\
                    • /pass or /password - Generate a secure password\n\n\
                    Password Generation Syntax:\n\
                    /pass [length] [options]\n\n\
                    Examples:\n\
                    • /pass - Default password (length: {})\n\
                    • /pass 24 - 24-character password\n\
                    • /pass 20 --symbols - Include symbols\n\
                    • /pass 16 --no-symbols - No symbols\n\
                    • /pass 18 --no-ambiguous - Exclude ambiguous chars (0,O,o,1,l,I)\n\
                    • /pass 20 --no-digits --symbols - No digits, with symbols\n\n\
                    Available Options:\n\
                    • --symbols / --no-symbols\n\
                    • --digits / --no-digits\n\
                    • --uppercase / --no-uppercase\n\
                    • --lowercase / --no-lowercase\n\
                    • --no-ambiguous - Exclude confusing characters\n\n\
                    Constraints:\n\
                    • Min length: {} characters\n\
                    • Max length: {} characters\n\
                    • At least one character type must be enabled\n\
                    • Rate limit: {} passwords per minute per chat\n\n\
                    Security Recommendations:\n\
                    ✅ Use long passwords (16+ characters)\n\
                    ✅ Use unique passwords for each account\n\
                    ✅ Store passwords in a secure password manager\n\
                    ⚠️ Remember: Telegram is not end-to-end encrypted\n\
                    ⚠️ This bot doesn't log passwords, but they travel through Telegram's servers",
                    state.config.default_password_length,
                    state.config.min_password_length,
                    state.config.max_password_length,
                    state.config.rate_limit_per_minute
                );

                let keyboard = teloxide::types::InlineKeyboardMarkup::new(vec![
                    vec![
                        InlineKeyboardButton::callback("📋 Default", "pass_default"),
                        InlineKeyboardButton::callback("🔒 Strong (24)", "pass_24"),
                    ],
                    vec![
                        InlineKeyboardButton::callback("🔤 No Symbols", "pass_no_symbols"),
                        InlineKeyboardButton::callback("🚫 Ambiguous", "pass_no_ambiguous"),
                    ],
                    vec![
                        InlineKeyboardButton::callback("🔐 Very Strong (32)", "pass_32"),
                        InlineKeyboardButton::callback("📏 Custom Length", "pass_custom"),
                    ],
                ]);

                bot.answer_callback_query(&q.id).await?;
                bot.send_message(q.from.id, help_text)
                    .reply_markup(keyboard)
                    .await?;
                return Ok(());
            }
            _ => return Ok(()),
        };

        // Create a fake message for password generation
        let chat_id = q.from.id;
        {
            let mut rate_limiter = state.rate_limiter.lock().await;
            if let Err(e) = rate_limiter.check_rate_limit(chat_id.0, state.config.rate_limit_per_minute) {
                bot.answer_callback_query(&q.id)
                    .text(e.to_string())
                    .await?;
                return Ok(());
            }
        }

        // Parse and generate password
        let mut password_config =
            match parse_password_args(&message.replace("/pass", "").trim(), state.config.default_password_length)
            {
                Ok(config) => config,
                Err(e) => {
                    bot.answer_callback_query(&q.id)
                        .text(format!("Error: {}", e))
                        .await?;
                    return Ok(());
                }
            };

        // Validate length bounds
        if password_config.length < state.config.min_password_length
            || password_config.length > state.config.max_password_length
        {
            bot.answer_callback_query(&q.id)
                .text("Invalid password length")
                .await?;
            return Ok(());
        }

        // Validate configuration
        if let Err(e) = password_config.validate() {
            bot.answer_callback_query(&q.id)
                .text(e.to_string())
                .await?;
            return Ok(());
        }

        // Generate password
        let mut rng = OsRng;
        let password = match generate_password(&password_config, &mut rng) {
            Ok(pwd) => pwd,
            Err(e) => {
                bot.answer_callback_query(&q.id)
                    .text(format!("Failed to generate: {}", e))
                    .await?;
                return Ok(());
            }
        };

        // Estimate strength
        let strength = estimate_strength(&password_config);
        let metadata = format_metadata(&password_config, strength);

        let strength_emoji = match strength {
            PasswordStrength::Strong => "💪",
            PasswordStrength::Medium => "👍",
            PasswordStrength::Weak => "⚠️",
        };

        let response = format!(
            "🔐 Your Secure Password:\n\n`{}`\n\n{} {}\n\n⚠️ Security reminder: Copy this password immediately and store it securely. This message will remain in your chat history.",
            password, strength_emoji, metadata
        );

        bot.answer_callback_query(&q.id).await?;
        bot.send_message(q.from.id, response).await?;

        info!(
            "Generated password via button for user {}: {}",
            q.from.id, metadata
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_password_args_default() {
        let config = parse_password_args("", 16).unwrap();
        assert_eq!(config.length, 16);
        assert!(config.use_lowercase);
        assert!(config.use_uppercase);
        assert!(config.use_digits);
        assert!(config.use_symbols);
    }

    #[test]
    fn test_parse_password_args_with_length() {
        let config = parse_password_args("24", 16).unwrap();
        assert_eq!(config.length, 24);
    }

    #[test]
    fn test_parse_password_args_with_options() {
        let config = parse_password_args("20 --no-symbols --no-ambiguous", 16).unwrap();
        assert_eq!(config.length, 20);
        assert!(!config.use_symbols);
        assert!(config.exclude_ambiguous);
    }

    #[test]
    fn test_parse_password_args_invalid_length() {
        let result = parse_password_args("abc", 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_password_args_unknown_option() {
        let result = parse_password_args("--invalid", 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::default();
        let chat_id = 12345;

        // Should allow up to the limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(chat_id, 5).is_ok());
        }

        // Should deny the next request
        assert!(limiter.check_rate_limit(chat_id, 5).is_err());
    }
}
