# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-11

### Added
- TOTP-based two-factor authentication with QR code setup
- Per-user enable/disable flow from the Roundcube settings panel
- Backup codes (6 single-use codes) generated on 2FA activation
- Dedicated `roundcube_2fa` database table — does not modify the Roundcube core `users` table
- Automatic table creation on first use (MySQL/MariaDB, PostgreSQL, SQLite)
- SQL files for manual database setup (`SQL/mysql.initial.sql`, `SQL/pgsql.initial.sql`, `SQL/sqlite.initial.sql`)
- CSRF token validation on all state-changing actions
- Session-based credential relay during the login 2FA step (5-minute expiry)
- Configurable issuer label and QR code size
- Optional server-side enforcement (`roundcube_2fa_force`)
- Localization support (English and Brazilian Portuguese)

### Security
- Backup codes generated with `random_int()` (CSPRNG) instead of `rand()`
- Credentials never exposed in HTML during the 2FA login step
- CSRF protection on enable and disable actions
