<?php
require_once __DIR__ . '/vendor/autoload.php';

use Endroid\QrCode\Builder\Builder;
use OTPHP\TOTP;

class roundcube_2fa extends rcube_plugin
{
    public $task = 'login|settings';

    function init()
    {
        $this->load_config();
        $this->add_texts('localization/');

        $this->add_hook('authenticate',     [$this, 'check_2fa']);
        $this->add_hook('settings_actions', [$this, 'settings_actions']);

        $this->register_action('plugin.roundcube_2fa',         [$this, 'settings_page']);
        $this->register_action('plugin.roundcube_2fa-setup',   [$this, 'setup']);
        $this->register_action('plugin.roundcube_2fa-verify',  [$this, 'verify_and_enable']);
        $this->register_action('plugin.roundcube_2fa-disable', [$this, 'disable']);

        $this->setup_database();
    }

    /* ================= SETTINGS ================= */

    function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.roundcube_2fa',
            'class'  => 'roundcube_2fa',
            'label'  => 'roundcube_2fa',
            'title'  => 'roundcube_2fa_title',
            'domain' => 'roundcube_2fa',
        ];
        return $args;
    }

    /* ================= LOGIN ================= */

    function check_2fa($args)
    {
        $rcmail = rcube::get_instance();
        $code   = isset($_POST['roundcube_2fa_code']) ? trim($_POST['roundcube_2fa_code']) : '';

        // Second submission: resume stored credentials and verify code
        if ($code !== '' && !empty($_SESSION['2fa_pending'])) {
            $pending = $_SESSION['2fa_pending'];

            if (time() - $pending['ts'] > 300) {
                unset($_SESSION['2fa_pending']);
                $this->show_login_form($args['user']);
                exit;
            }

            $data = $this->get_user_data($pending['user']);

            if ($this->verify_totp($data['twofa_secret'], $code) || $this->verify_backup($code, $data)) {
                unset($_SESSION['2fa_pending']);
                $args['user'] = $pending['user'];
                $args['pass'] = $pending['pass'];
                return $args;
            }

            $rcmail->output->show_message($this->gettext('roundcube_2fa_invalid'), 'error');
            $this->show_login_form($pending['user']);
            exit;
        }

        // First submission: check if user has 2FA enabled
        $data = $this->get_user_data($args['user']);
        if (!$data || !$data['twofa_enabled']) return $args;

        $_SESSION['2fa_pending'] = ['user' => $args['user'], 'pass' => $args['pass'], 'ts' => time()];
        $this->show_login_form($args['user']);
        exit;
    }

    function show_login_form($username = '')
    {
        $rcmail = rcube::get_instance();
        $rcmail->output->assign('two_fa_username', htmlspecialchars($username));
        $rcmail->output->send('roundcube_2fa');
    }

    /* ================= SETUP ================= */

    function setup()
    {
        $rcmail = rcube::get_instance();
        $secret = $this->generate_secret();
        $_SESSION['2fa_tmp_secret'] = $secret;

        $rcmail->output->assign('qr', $this->get_qr($rcmail->get_user_name(), $secret));
        $rcmail->output->send('setup');
    }

    function verify_and_enable()
    {
        $rcmail = rcube::get_instance();

        if (!rcube_utils::check_request_token()) {
            $rcmail->output->show_message('Invalid request', 'error');
            $this->settings_page();
            return;
        }

        $code   = rcube_utils::get_input_value('_code', rcube_utils::INPUT_POST);
        $secret = $_SESSION['2fa_tmp_secret'] ?? null;

        if ($this->verify_totp($secret, $code)) {
            $backup_codes = $this->generate_backup_codes();
            $this->upsert_user([
                'secret'       => $secret,
                'enabled'      => 1,
                'backup_codes' => json_encode($backup_codes),
            ]);
            unset($_SESSION['2fa_tmp_secret']);
            $rcmail->output->assign('two_fa_backup_codes', $backup_codes);
            $rcmail->output->show_message($this->gettext('2fa_enabled_success'), 'confirmation');
        } else {
            $rcmail->output->show_message($this->gettext('invalid_verification_code'), 'error');
        }

        $rcmail->overwrite_action('plugin.roundcube_2fa');
        $this->settings_page();
    }

    function disable()
    {
        $rcmail = rcube::get_instance();

        if (!rcube_utils::check_request_token()) {
            $rcmail->output->show_message('Invalid request', 'error');
            $this->settings_page();
            return;
        }

        $this->upsert_user(['secret' => null, 'enabled' => 0, 'backup_codes' => null]);
        $rcmail->output->show_message($this->gettext('2fa_disabled_success'), 'confirmation');
        $this->settings_page();
    }

    function settings_page()
    {
        $rcmail = rcube::get_instance();
        $data   = $this->get_user_data($rcmail->get_user_name());
        $rcmail->output->assign('two_fa_enabled', !empty($data['twofa_enabled']));
        $rcmail->output->send('settings_page');
    }

    /* ================= TOTP ================= */

    function verify_totp($secret, $code)
    {
        if (!$secret || !$code) return false;
        return TOTP::create($secret)->verify((string) $code);
    }

    function get_qr($user, $secret)
    {
        $rcmail = rcube::get_instance();
        $totp   = TOTP::create($secret);
        $totp->setLabel($user);
        $totp->setIssuer($rcmail->config->get('roundcube_2fa_issuer', 'Roundcube'));

        return Builder::create()
            ->data($totp->getProvisioningUri())
            ->size((int) $rcmail->config->get('roundcube_2fa_qr_size', 200))
            ->margin(10)
            ->build()
            ->getDataUri();
    }

    /* ================= BACKUP ================= */

    function generate_backup_codes()
    {
        $codes = [];
        for ($i = 0; $i < 6; $i++) $codes[] = strval(random_int(100000, 999999));
        return $codes;
    }

    function verify_backup($code, $data)
    {
        $codes = json_decode($data['twofa_backup_codes'], true) ?? [];
        if (!in_array($code, $codes, true)) return false;

        $codes = array_values(array_diff($codes, [$code]));
        $db    = rcube::get_instance()->get_dbh();
        $db->query(
            "UPDATE " . $db->table_name('roundcube_2fa', true) . " SET backup_codes = ? WHERE user_id = ?",
            [json_encode($codes), $data['user_id']]
        );
        return true;
    }

    /* ================= DATABASE ================= */

    function get_user_data($username)
    {
        $db    = rcube::get_instance()->get_dbh();
        $users = $db->table_name('users', true);
        $twofa = $db->table_name('roundcube_2fa', true);

        $result = $db->query(
            "SELECT u.user_id, t.secret AS twofa_secret, t.enabled AS twofa_enabled," .
            " t.backup_codes AS twofa_backup_codes" .
            " FROM $users u LEFT JOIN $twofa t ON t.user_id = u.user_id" .
            " WHERE u.username = ?",
            [$username]
        );
        return $db->fetch_assoc($result);
    }

    function upsert_user($fields)
    {
        $rcmail  = rcube::get_instance();
        $db      = $rcmail->get_dbh();
        $user_id = $rcmail->user->ID;
        $table   = $db->table_name('roundcube_2fa', true);

        $existing = $db->query("SELECT user_id FROM $table WHERE user_id = ?", [$user_id]);

        if ($db->fetch_assoc($existing)) {
            $sets = $params = [];
            foreach ($fields as $col => $val) {
                $sets[]   = "$col = ?";
                $params[] = $val;
            }
            $params[] = $user_id;
            $db->query("UPDATE $table SET " . implode(', ', $sets) . " WHERE user_id = ?", $params);
        } else {
            $fields['user_id'] = $user_id;
            $db->query(
                "INSERT INTO $table (" . implode(', ', array_keys($fields)) . ")" .
                " VALUES (" . implode(', ', array_fill(0, count($fields), '?')) . ")",
                array_values($fields)
            );
        }
    }

    function generate_secret()
    {
        return TOTP::create()->getSecret();
    }

    private function setup_database()
    {
        $db    = rcube::get_instance()->get_dbh();
        $table = $db->table_name('roundcube_2fa', true);

        // Skip if table already exists
        $result = $db->query("SELECT 1 FROM $table LIMIT 1");
        if (!$db->is_error($result)) return;

        switch ($db->db_provider) {
            case 'mysql':
            case 'mysqli':
                $db->query("CREATE TABLE IF NOT EXISTS $table (
                    `user_id` int(10) UNSIGNED NOT NULL,
                    `secret` varchar(64) DEFAULT NULL,
                    `enabled` tinyint(1) NOT NULL DEFAULT 0,
                    `backup_codes` text DEFAULT NULL,
                    PRIMARY KEY (`user_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
                break;
            case 'pgsql':
                $db->query("CREATE TABLE IF NOT EXISTS $table (
                    user_id integer NOT NULL,
                    secret varchar(64) DEFAULT NULL,
                    enabled smallint NOT NULL DEFAULT 0,
                    backup_codes text DEFAULT NULL,
                    PRIMARY KEY (user_id)
                )");
                break;
            case 'sqlite':
                $db->query("CREATE TABLE IF NOT EXISTS $table (
                    user_id integer NOT NULL,
                    secret varchar(64) DEFAULT NULL,
                    enabled integer NOT NULL DEFAULT 0,
                    backup_codes text DEFAULT NULL,
                    PRIMARY KEY (user_id)
                )");
                break;
        }
    }
}
