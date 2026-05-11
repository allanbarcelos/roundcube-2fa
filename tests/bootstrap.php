<?php
declare(strict_types=1);

// Load Composer autoloader (endroid/qr-code, spomky-labs/otphp, PHPUnit)
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Load Roundcube framework stubs (order matters: dependencies first)
require_once __DIR__ . '/stubs/rcube_plugin.php';
require_once __DIR__ . '/stubs/rcube_db.php';
require_once __DIR__ . '/stubs/rcube_output.php';
require_once __DIR__ . '/stubs/rcube_config.php';
require_once __DIR__ . '/stubs/rcube_user.php';
require_once __DIR__ . '/stubs/rcube.php';
require_once __DIR__ . '/stubs/rcube_utils.php';

// Load the plugin class (vendor autoload already active, stubs satisfy all dependencies)
require_once dirname(__DIR__) . '/roundcube_2fa.php';
