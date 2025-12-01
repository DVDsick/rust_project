/// Telegram Password Generator Bot - Main entry point.
///
/// This bot generates cryptographically secure random passwords on demand
/// via Telegram commands. It uses OS-level randomness (OsRng) and provides
/// configurable password generation with strength estimation.
///
/// Security considerations:
/// - Passwords are generated using cryptographically secure randomness
/// - Passwords are NEVER logged or stored server-side
/// - Rate limiting prevents abuse
/// - Telegram messages are not end-to-end encrypted
mod bot;
mod config;
mod error;
mod password;

use bot::{handle_help, handle_password, handle_start, handle_unknown, BotState};
use config::Config;
use error::Result;
use teloxide::dispatching::{dialogue, UpdateFilterExt};
use teloxide::prelude::*;
use teloxide::types::Update;
use teloxide::utils::command::BotCommands;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Telegram bot commands.
#[derive(BotCommands, Clone)]
#[command(
    rename_rule = "lowercase",
    description = "Secure Password Generator Bot Commands:"
)]
enum Command {
    #[command(description = "Start the bot and see welcome message")]
    Start,
    #[command(description = "Show help and usage information")]
    Help,
    #[command(description = "Generate a secure password (alias: /password)")]
    Pass(String),
    #[command(description = "Generate a secure password")]
    Password(String),
}

/// Main bot message handler.
async fn handle_command(
    bot: Bot,
    msg: Message,
    cmd: Command,
    state: BotState,
) -> ResponseResult<()> {
    match cmd {
        Command::Start => handle_start(bot, msg).await,
        Command::Help => handle_help(bot, msg, state).await,
        Command::Pass(args) | Command::Password(args) => {
            handle_password(bot, msg, state, args).await
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing/logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "telegram_password_bot=info,teloxide=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Telegram Password Generator Bot...");

    // Load .env file if present (for development)
    if let Err(e) = dotenvy::dotenv() {
        info!("No .env file found or error loading it: {}", e);
    }

    // Load configuration from environment variables
    let config = Config::from_env().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    info!("Configuration loaded successfully");
    info!(
        "Default password length: {}",
        config.default_password_length
    );
    info!(
        "Password length range: {}-{}",
        config.min_password_length, config.max_password_length
    );
    info!(
        "Rate limit: {} requests per minute per chat",
        config.rate_limit_per_minute
    );

    // Create bot instance
    let bot = Bot::new(&config.bot_token);

    info!("Bot initialized, starting dispatcher...");

    // Create shared state
    let state = BotState::new(config);

    // Set up command handler
    let handler = Update::filter_message()
        .branch(
            dptree::entry()
                .filter_command::<Command>()
                .endpoint(handle_command),
        )
        .branch(dptree::endpoint(handle_unknown));

    // Start the dispatcher
    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    info!("Bot stopped");

    Ok(())
}
