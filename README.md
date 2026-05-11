# Roundcube 2FA

![PHP](https://img.shields.io/badge/PHP-%3E%3D7.4-8892BF)
![Roundcube](https://img.shields.io/badge/Roundcube-%3E%3D1.5-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

A two-factor authentication (2FA) plugin for [Roundcube](https://roundcube.net/) webmail using Time-based One-Time Passwords (TOTP). Compatible with Google Authenticator, Microsoft Authenticator, Authy, and any RFC 6238-compliant app.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- TOTP-based 2FA setup per user via QR code
- Backup codes for account recovery (6 single-use codes, cryptographically generated)
- Optional server-side enforcement for all users
- CSRF protection on all sensitive actions
- Automatic database table creation on first use
- Full support for MySQL/MariaDB, PostgreSQL, and SQLite
- Respects Roundcube table prefix configuration

---

## Requirements

| Dependency | Version |
|---|---|
| PHP | >= 7.4 |
| Roundcube | >= 1.5 |
| endroid/qr-code | ^4.0 |
| spomky-labs/otphp | ^11.0 |

---

## Installation

### Option A — Composer (recommended)

From your Roundcube root directory:

```bash
composer require allanbarcelos/roundcube-2fa
```

### Option B — Manual

```bash
cd /path/to/roundcube/plugins
git clone https://github.com/allanbarcelos/roundcube-2fa
cd roundcube-2fa
composer install --no-dev --optimize-autoloader
```

### Enable the plugin

Add `roundcube-2fa` to the plugins list in `config/config.inc.php`:

```php
$config['plugins'] = ['roundcube-2fa'];
```

---

## Database Setup

The plugin **automatically creates** its own table (`roundcube_2fa`) on first use — no manual step required for standard installations.

### Manual setup

If you prefer to create the table yourself, or if you use a restricted database user, run the file matching your database engine from the `SQL/` directory:

```bash
# MySQL / MariaDB
mysql -u <user> -p <database> < plugins/roundcube-2fa/SQL/mysql.initial.sql

# PostgreSQL
psql -U <user> <database> < plugins/roundcube-2fa/SQL/pgsql.initial.sql

# SQLite
sqlite3 /path/to/roundcube.db < plugins/roundcube-2fa/SQL/sqlite.initial.sql
```

> **Table prefix:** If your Roundcube installation uses a table prefix (e.g. `rc_`), rename `roundcube_2fa` to `rc_roundcube_2fa` in the SQL file before running it. The plugin reads the prefix from your Roundcube configuration automatically.

---

## Configuration

Copy `config.inc.php.sample` to `config.inc.php` inside the plugin directory, then adjust the values:

```php
<?php

// Force 2FA for all users. Users cannot disable it when this is true.
// Default: false
$config['roundcube_2fa_force'] = false;

// Number of single-use backup codes generated when 2FA is enabled.
// Default: 6
$config['roundcube_2fa_backup_codes'] = 6;

// Width and height of the QR code image, in pixels.
// Default: 200
$config['roundcube_2fa_qr_size'] = 200;

// Issuer label shown in the authenticator app alongside the account name.
// Default: 'Roundcube'
$config['roundcube_2fa_issuer'] = 'Roundcube';
```

---

## Usage

### Enabling 2FA (end user)

1. Log in to Roundcube.
2. Go to **Settings → Two Factor Authentication**.
3. Click **Set up 2FA**.
4. Scan the QR code with your authenticator app.
5. Enter the 6-digit code from the app to confirm.
6. **Save your backup codes** — they are shown only once and cannot be recovered.

### Logging in with 2FA active

After entering your username and password, you will be prompted for your TOTP code. Enter the 6-digit code from your authenticator app to complete login.

### Using a backup code

If you no longer have access to your authenticator app, enter one of your backup codes in the TOTP field. Each code can only be used once. If all backup codes are exhausted, contact your server administrator.

### Disabling 2FA

Go to **Settings → Two Factor Authentication** and click **Disable 2FA**. You will be asked to confirm. This action immediately revokes the TOTP secret and all remaining backup codes.

---

## Security

- **TOTP secrets** are stored in a dedicated `roundcube_2fa` table, isolated from the Roundcube core `users` table.
- **Backup codes** are generated with `random_int()` (CSPRNG) and stored in the database. Each code is deleted after use.
- **CSRF tokens** are validated on all state-changing actions (enable, disable).
- **Session-based credential relay:** credentials are stored in the server-side session during the 2FA step and never exposed in the HTML. The session entry expires after 5 minutes.
- **HTTPS is strongly recommended.** Without it, TOTP codes transmitted over the network can be intercepted.

---

## Troubleshooting

**The 2FA option does not appear in Settings.**
Verify that `roundcube-2fa` is listed in `$config['plugins']` and that `composer install` has been run inside the plugin directory.

**"Invalid code" even with the correct TOTP code.**
TOTP is time-sensitive. Ensure the server clock is synchronized (e.g. via NTP). A drift of more than 30 seconds will cause verification to fail.

**Locked out after losing access to the authenticator app.**
Use one of your backup codes. If all backup codes are gone, ask your server administrator to run:

```sql
UPDATE roundcube_2fa SET enabled = 0, secret = NULL, backup_codes = NULL
WHERE user_id = (SELECT user_id FROM users WHERE username = 'your@email.com');
```

**The plugin fails to create the database table.**
The database user may lack `CREATE TABLE` privileges. Run the appropriate SQL file from `SQL/` manually using a privileged account.

---

## Contributing

Bug reports and pull requests are welcome. Please open an issue before submitting a pull request for significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Commit your changes
4. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE)
