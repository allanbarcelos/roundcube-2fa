<?php
require_once __DIR__ . '/vendor/autoload.php';

use Endroid\QrCode\Builder\Builder;
use OTPHP\TOTP;

class roundcube_2fa extends rcube_plugin
{
    public $task = '*';

    function init()
    {
        $this->rc = rcmail::get_instance();

        $this->load_config();

        $this->add_texts('localization/'); 

        // Hooks
        $this->add_hook('authenticate', [$this, 'check_2fa']);
        $this->add_hook('settings_actions', [$this, 'settings_actions']);

        // Actions
        $this->register_action('plugin.roundcube_2fa', [$this, 'settings_page']);
        $this->register_action('plugin.roundcube_2fa-setup', [$this, 'setup']);
        $this->register_action('plugin.roundcube_2fa-verify', [$this, 'verify_and_enable']);
        $this->register_action('plugin.roundcube_2fa-disable', [$this, 'disable']);
        $this->register_action('plugin.roundcube_2fa-settings', [$this, 'settings_page']);

        if (empty($_SESSION['2fa_db_ready'])) {
            $this->setup_database();
            $_SESSION['2fa_db_ready'] = true;
        }
    }

    /* ================= SEÇÃO DE CONFIGURAÇÕES ================= */

    function settings_actions($args)
    {
        // register as settings action
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

        // Segunda submissão: retoma credenciais da sessão
        if ($code !== '' && !empty($_SESSION['2fa_pending'])) {
            $pending = $_SESSION['2fa_pending'];

            // Sessão expirou (mais de 5 minutos)
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

        // Primeira submissão: verifica se o usuário tem 2FA ativo
        $user = $args['user'];
        $data = $this->get_user_data($user);
        if (!$data || !$data['twofa_enabled']) return $args;

        // Armazena credenciais na sessão e exibe formulário 2FA
        $_SESSION['2fa_pending'] = [
            'user' => $args['user'],
            'pass' => $args['pass'],
            'ts'   => time(),
        ];

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

        $qr = $this->get_qr($rcmail->get_user_name(), $secret);

        $rcmail->output->assign('qr', $qr);
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
        $code = rcube_utils::get_input_value('_code', rcube_utils::INPUT_POST);
        $secret = $_SESSION['2fa_tmp_secret'];

        if ($this->verify_totp($secret, $code)) {
            $backup_codes = $this->generate_backup_codes();
            $this->update_user([
                'twofa_enabled' => 1,
                'twofa_secret' => $secret,
                'twofa_backup_codes' => json_encode($backup_codes)
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
        $this->update_user([
            'twofa_enabled' => 0,
            'twofa_secret' => null,
            'twofa_backup_codes' => null
        ]);
        $rcmail->output->show_message($this->gettext('2fa_disabled_success'), 'confirmation');
        $this->settings_page();
    }

    function settings_page() {
        $rcmail = rcube::get_instance();
        $data = $this->get_user_data($rcmail->get_user_name());
        $rcmail->output->assign('two_fa_enabled', !empty($data['twofa_enabled']));
        $rcmail->output->send('settings_page');
    }


    /* ================= TOTP ================= */
    function verify_totp($secret, $code)
    {
        $totp = TOTP::create($secret);
        return $totp->verify($code);
    }

    function get_qr($user, $secret)
    {
        $rcmail = rcube::get_instance();
        $issuer = $rcmail->config->get('roundcube_2fa_issuer', 'Roundcube');
        $size   = (int) $rcmail->config->get('roundcube_2fa_qr_size', 200);

        $totp = TOTP::create($secret);
        $totp->setLabel($user);
        $totp->setIssuer($issuer);

        $result = Builder::create()
            ->data($totp->getProvisioningUri())
            ->size($size)
            ->margin(10)
            ->build();

        return $result->getDataUri();
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
        if (!in_array($code, $codes)) return false;

        // Remove código usado
        $codes = array_diff($codes, [$code]);
        $this->save_backup($codes);
        return true;
    }

    function save_backup($codes)
    {
        $this->update_user(['twofa_backup_codes' => json_encode(array_values($codes))]);
    }

    /* ================= HELPERS ================= */
    function get_user_data($user)
    {
        $rcmail = rcube::get_instance();
        $db = $rcmail->get_dbh();

        // Prepare the query
        $result = $db->query("SELECT * FROM users WHERE username = ?", [$user]);

        if (!$result) {
            return null;
        }

        // fetch_assoc() returns the associative array directly
        return $db->fetch_assoc($result); 
    }

    function update_user($fields)
    {
        $rcmail = rcube::get_instance();
        $db = $rcmail->get_dbh();
        $user = $rcmail->get_user_name();

        if (empty($fields)) {
            return;
        }

        $set_clauses = [];
        $params = [];

        foreach ($fields as $col => $value) {
            $set_clauses[] = "$col = ?";
            $params[] = $value;
        }

        // Add the username for the WHERE clause
        $params[] = $user;
        
        $query = "UPDATE users SET " . implode(', ', $set_clauses) . " WHERE username = ?";
        $db->query($query, $params);
    }

    function generate_secret()
    {
        $totp = TOTP::create();
        return $totp->getSecret();
    }
    
    /* ================= DATABASE SETUP ================= */

    private function setup_database()
    {
        $rcmail = rcube::get_instance();
        $dbh = $rcmail->get_dbh();
        $driver = $dbh->db_provider; // mysql / sqlite / pgsql

        $columns = [
            'twofa_secret' => "VARCHAR(64)",
            'twofa_enabled' => "TINYINT(1) DEFAULT 0",
            'twofa_backup_codes' => "TEXT"
        ];

        $table = "users";

        foreach ($columns as $col => $type) {
            if ($driver === 'sqlite') {
                // SQLite: consulta PRAGMA
                $res = $dbh->query("PRAGMA table_info($table)");
                $exists = false;
                while ($row = $dbh->fetch_assoc($res)) {
                    if ($row['name'] === $col) {
                        $exists = true;
                        break;
                    }
                }
            } else {
                // MySQL / MariaDB
                $exists = $dbh->fetchOne("SHOW COLUMNS FROM `$table` LIKE ?", [$col]);
            }

            if (!$exists) {
                $dbh->query("ALTER TABLE `$table` ADD COLUMN `$col` $type");
            }
        }
    }


}
