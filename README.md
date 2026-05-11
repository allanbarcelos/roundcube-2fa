# Roundcube 2FA

Two-factor authentication (TOTP) plugin for [Roundcube](https://roundcube.net/) webmail.

Compatible with Google Authenticator, Microsoft Authenticator, Authy, and any TOTP-compliant app.

## Requirements

| Dependency | Version |
|---|---|
| PHP | >= 7.4 |
| Roundcube | >= 1.5 |

## Features

- Per-user TOTP setup via QR code
- Backup codes for account recovery (6 single-use codes)
- Optional forced 2FA for all users
- Supports MySQL, PostgreSQL, and SQLite
- Compatible with any TOTP app (RFC 6238)

## Installation

### 1. Install via Composer (recommended)

```bash
cd /path/to/roundcube
composer require allanbarcelos/roundcube-2fa
```

### 2. Manual installation

```bash
cd /path/to/roundcube/plugins
git clone https://github.com/allanbarcelos/roundcube-2fa
cd roundcube-2fa
composer install --no-dev
```

### 3. Enable the plugin

Add to `config/config.inc.php`:

```php
$config['plugins'] = ['roundcube-2fa'];
```

### 4. Database

The plugin creates its own table (`roundcube_2fa`) automatically on first use.

For manual setup, run the appropriate file from the `SQL/` directory:

```bash
# MySQL / MariaDB
mysql -u user -p roundcube < plugins/roundcube-2fa/SQL/mysql.initial.sql

# PostgreSQL
psql -U user roundcube < plugins/roundcube-2fa/SQL/pgsql.initial.sql

# SQLite
sqlite3 /path/to/roundcube.db < plugins/roundcube-2fa/SQL/sqlite.initial.sql
```

> If you use a Roundcube table prefix (e.g. `rc_`), rename the table in the SQL file accordingly before running it.

## Configuration

Copy `config.inc.php.sample` to `config.inc.php` and adjust as needed:

```php
// Force 2FA for all users (default: false)
$config['roundcube_2fa_force'] = false;

// Number of backup codes generated (default: 6)
$config['roundcube_2fa_backup_codes'] = 6;

// QR code size in pixels (default: 200)
$config['roundcube_2fa_qr_size'] = 200;

// Issuer name shown in the authenticator app (default: 'Roundcube')
$config['roundcube_2fa_issuer'] = 'Roundcube';
```

## Usage

1. Log in to Roundcube
2. Go to **Settings → Two Factor Authentication**
3. Click **Set up 2FA** and scan the QR code with your authenticator app
4. Enter the 6-digit code to confirm and activate
5. Save the backup codes shown — they are only displayed once

On your next login, you will be prompted for your TOTP code after entering your password.

## License

MIT — see [LICENSE](LICENSE)
