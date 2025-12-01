# Telegram Password Generator Bot 🔐

A production-quality Telegram bot written in Rust that generates cryptographically secure random passwords on demand. This project is designed as a defensive cybersecurity tool suitable for university-level Rust and cybersecurity coursework.

## Features

- **Cryptographically Secure**: Uses OS-level randomness (`OsRng`) for password generation
- **Highly Configurable**: Customize password length, character types, and complexity
- **Strength Estimation**: Automatic entropy calculation and password strength assessment
- **Rate Limiting**: Built-in protection against abuse (configurable requests per minute)
- **Privacy-Focused**: Passwords are never logged or stored server-side
- **Well-Tested**: Comprehensive unit tests for core functionality
- **Production-Ready**: Structured logging, error handling, and graceful shutdown

## Security Disclaimer ⚠️

- **Cryptographic Security**: This bot uses `rand::rngs::OsRng`, which provides cryptographically secure random number generation based on OS entropy sources.
- **No Logging**: Generated passwords are NEVER written to logs or stored on the server. Only metadata (length, character types, entropy) is logged.
- **Telegram Limitations**: Telegram messages are **not end-to-end encrypted**. Passwords sent via this bot travel through Telegram's servers and may be visible to Telegram and the devices involved.
- **Intended Use**: This bot is a convenience tool. For maximum security, consider using an offline password generator or a dedicated password manager.
- **Rate Limiting**: The bot implements per-chat rate limiting to prevent abuse and excessive requests.

## Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/) (stable channel)
- **Telegram Bot Token**: Obtain from [@BotFather](https://t.me/BotFather) on Telegram

## Installation & Setup

### 1. Clone or Download the Project

```bash
cd rust_project
```

### 2. Configure Environment Variables

Create a `.env` file in the project root (use `.env.example` as a template):

```bash
# Required: Your Telegram bot token from @BotFather
TELEGRAM_BOT_TOKEN=your_bot_token_here

# Optional: Customize bot behavior
DEFAULT_PASSWORD_LENGTH=16
MAX_PASSWORD_LENGTH=64
MIN_PASSWORD_LENGTH=8
RATE_LIMIT_PER_MINUTE=10
```

**Getting a Bot Token:**
1. Open Telegram and search for [@BotFather](https://t.me/BotFather)
2. Send `/newbot` and follow the instructions
3. Copy the token provided by BotFather
4. Paste it into your `.env` file

### 3. Build the Project

```bash
cargo build --release
```

### 4. Run the Bot

```bash
cargo run --release
```

Alternatively, after building, you can run the binary directly:

```bash
./target/release/telegram-password-bot
```

## Usage

Once the bot is running, open Telegram and start a chat with your bot.

### Available Commands

#### `/start`
Start the bot and see a welcome message with basic usage information.

#### `/help`
Display detailed help including all available commands, options, and security recommendations.

#### `/pass` or `/password`
Generate a secure random password.

**Syntax:**
```
/pass [length] [options]
```

**Examples:**

- `/pass` - Generate a password with default settings (16 characters, all character types)
- `/pass 24` - Generate a 24-character password
- `/pass 20 --symbols` - 20-character password with symbols included
- `/pass 16 --no-symbols` - 16-character password without symbols
- `/pass 20 --no-ambiguous` - 20-character password excluding ambiguous characters (0, O, o, 1, l, I)
- `/pass 24 --no-digits --symbols` - 24-character password with symbols but no digits
- `/pass 32 --no-uppercase --no-symbols` - 32-character lowercase + digits only

### Available Options

| Option | Effect |
|--------|--------|
| `--symbols` | Include symbols (!@#$%^&*...) |
| `--no-symbols` | Exclude symbols |
| `--digits` | Include digits (0-9) |
| `--no-digits` | Exclude digits |
| `--uppercase` | Include uppercase letters (A-Z) |
| `--no-uppercase` | Exclude uppercase letters |
| `--lowercase` | Include lowercase letters (a-z) |
| `--no-lowercase` | Exclude lowercase letters |
| `--no-ambiguous` | Exclude ambiguous characters (0, O, o, 1, l, I) |

### Password Strength

The bot automatically estimates password strength based on entropy:

- **Weak** (⚠️): < 50 bits of entropy
- **Medium** (👍): 50-80 bits of entropy
- **Strong** (💪): ≥ 80 bits of entropy

Entropy is calculated as: `length × log₂(pool_size)`

## Project Structure

```
rust_project/
├── Cargo.toml          # Project dependencies and metadata
├── README.md           # This file
├── .env.example        # Example environment configuration
├── .gitignore          # Git ignore rules
└── src/
    ├── main.rs         # Entry point, bot initialization
    ├── bot.rs          # Telegram command handlers and rate limiting
    ├── config.rs       # Configuration management
    ├── password.rs     # Password generation and strength estimation
    └── error.rs        # Custom error types
```

## Development

### Running Tests

```bash
cargo test
```

Tests cover:
- Password generation correctness (length, character types)
- Exclusion of ambiguous characters
- Configuration validation
- Argument parsing
- Rate limiting logic
- Strength estimation

### Code Quality

Run Clippy for linting:

```bash
cargo clippy -- -D warnings
```

Format code:

```bash
cargo fmt
```

### Logging

The bot uses `tracing` for structured logging. Set the log level via the `RUST_LOG` environment variable:

```bash
RUST_LOG=telegram_password_bot=debug cargo run
```

## Configuration Reference

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | String | **(required)** | Bot token from @BotFather |
| `DEFAULT_PASSWORD_LENGTH` | Integer | 16 | Default password length |
| `MAX_PASSWORD_LENGTH` | Integer | 64 | Maximum allowed password length |
| `MIN_PASSWORD_LENGTH` | Integer | 8 | Minimum allowed password length |
| `RATE_LIMIT_PER_MINUTE` | Integer | 10 | Max password requests per chat per minute |

## Security Best Practices

When using this bot:

✅ **DO:**
- Use long passwords (16+ characters recommended)
- Use unique passwords for each account
- Store passwords in a secure password manager
- Copy passwords immediately and clear chat history if needed
- Use `--no-ambiguous` for passwords you'll type manually

⚠️ **DON'T:**
- Share passwords sent via Telegram with untrusted parties
- Rely solely on this bot for highly sensitive accounts (use offline generators)
- Exceed rate limits (respect the bot's abuse prevention)

## Technical Details

### Randomness Source

The bot uses `rand::rngs::OsRng`, which provides:
- **Linux/BSD**: `/dev/urandom`
- **Windows**: `BCryptGenRandom` (CNG API)
- **macOS/iOS**: `SecRandomCopyBytes`
- **WASM**: `crypto.getRandomValues` (browser) or `getrandom` syscall (WASI)

All sources are cryptographically secure random number generators (CSRNGs).

### Password Generation Algorithm

1. Build character pool from enabled character types (lowercase, uppercase, digits, symbols)
2. If `--no-ambiguous` is set, remove confusing characters (0, O, o, 1, l, I)
3. Ensure at least one character from each enabled category
4. Fill remaining positions with random characters from the pool
5. Shuffle the result to avoid predictable patterns

### Rate Limiting

- Implemented in-memory per chat ID
- Tracks timestamps of requests in the last 60 seconds
- Configurable limit (default: 10 requests/minute)
- Cleans up old entries automatically

## Dependencies

Key dependencies:
- `teloxide`: Telegram bot framework
- `tokio`: Async runtime
- `rand` + `rand_core`: Cryptographically secure randomness
- `tracing`: Structured logging
- `thiserror`: Error handling
- `dotenvy`: Environment variable loading

See `Cargo.toml` for complete dependency list and versions.

## License

This project is provided as-is for educational purposes. Use responsibly and at your own risk.

## Contributing

This is an educational project. Contributions, improvements, and feedback are welcome!

## Troubleshooting

### Bot doesn't start

- **Check token**: Ensure `TELEGRAM_BOT_TOKEN` is set correctly in `.env`
- **Check network**: Verify internet connectivity and Telegram API accessibility
- **Check logs**: Look for error messages in the console output

### Rate limit errors

- Wait 60 seconds before trying again
- Consider increasing `RATE_LIMIT_PER_MINUTE` in `.env`

### Build errors

- Update Rust: `rustup update`
- Clean build artifacts: `cargo clean && cargo build`

## Contact

For issues related to Telegram bot functionality, consult the [teloxide documentation](https://docs.rs/teloxide/).

---

**Built with Rust 🦀 | Secure by Design 🔐**
