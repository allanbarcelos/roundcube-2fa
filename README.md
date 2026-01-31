# 2FA Plugin

Two-Factor Authentication plugin for Roundcube.

## Features

- Enable/disable 2FA per user
- Support for time-based one-time passwords (TOTP)
- QR code generation for easy setup
- Backup codes for account recovery

## Installation

1. Clone or extract to `plugins/2fa/`
2. Enable the plugin in Roundcube config
3. Run database migrations if needed

## Configuration

Add to `config/config.inc.php`:

```php
$config['plugins'] = array('2fa');
```

## Usage

Users can enable 2FA in their account settings and scan the QR code with an authenticator app.
