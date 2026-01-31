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

        // Hooks
        $this->add_hook('authenticate', [$this, 'check_2fa']);
        $this->add_hook('preferences_sections', [$this, 'preferences_sections']);
        $this->add_hook('preferences_list', [$this, 'preferences_list']);

        // Actions
        $this->register_action('plugin.roundcube_2fa-setup', [$this, 'setup']);
        $this->register_action('plugin.roundcube_2fa-verify', [$this, 'verify_and_enable']);
        $this->register_action('plugin.roundcube_2fa-disable', [$this, 'disable']);
        $this->register_action('plugin.roundcube_2fa-settings', [$this, 'settings_page']);

        $this->setup_database();
    }

    /* ================= SEÇÃO DE CONFIGURAÇÕES ================= */

    function preferences_sections($args)
    {
        $args['list']['2fa_section'] = [
            'id' => '2fa_section',
            'section' => '2fa_section',
            'title'   => $this->gettext('roundcube_2fa_title')
        ];
        return $args;
    }

    function preferences_list($args)
    {
        if ($args['section'] == '2fa_section') {
            $rcmail = rcube::get_instance();
            $user_data = $this->get_user_data($rcmail->get_user_name());
            $enabled = !empty($user_data['twofa_enabled']);

            $args['blocks']['main']['name'] = $this->gettext('roundcube_2fa_title');

            if ($enabled) {
                $status = '<span style="color:green; font-weight:bold;">' . $this->gettext('enabled') . '</span>';
                $button = '<p><a href="./?_task=settings&_action=plugin.roundcube_2fa-disable" class="button mainaction">' . $this->gettext('disable_2fa') . '</a></p>';
            } else {
                $status = '<span style="color:red; font-weight:bold;">' . $this->gettext('disabled') . '</span>';
                $button = '<p><a href="./?_task=settings&_action=plugin.roundcube_2fa-setup" class="button mainaction">' . $this->gettext('setup_2fa') . '</a></p>';
            }

            $args['blocks']['main']['options']['status'] = [
                'title' => $this->gettext('status'),
                'content' => $status . $button
            ];
        }
        return $args;
    }

    /* ================= LOGIN ================= */
    function check_2fa($args)
    {
        $rcmail = rcube::get_instance();
        $user = $args['user'];

        $data = $this->get_user_data($user);
        if (!$data || !$data['twofa_enabled']) return $args;

        // Se o token não foi enviado ainda
        if (empty($_POST['roundcube_2fa_code'])) {
            $this->show_form();
            exit;
        }

        if ($this->verify_totp($data['twofa_secret'], $_POST['roundcube_2fa_code'])) {
            return $args;
        }

        if ($this->verify_backup($_POST['roundcube_2fa_code'], $data)) {
            return $args;
        }

        $rcmail->output->show_message($this->gettext('roundcube_2fa_invalid'), 'error');
        $this->show_form();
        exit;
    }

    function show_form()
    {
        rcube::get_instance()->output->send('roundcube_2fa');
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
            $rcmail->output->show_message($this->gettext('2fa_enabled_success'), 'confirmation');
        } else {
            $rcmail->output->show_message($this->gettext('invalid_verification_code'), 'error');
        }
        
        $rcmail->overwrite_action('plugin.roundcube_2fa-settings');
        $this->settings_page();
    }

    function disable()
    {
        $this->update_user([
            'twofa_enabled' => 0,
            'twofa_secret' => null,
            'twofa_backup_codes' => null
        ]);
        rcube::get_instance()->output->show_message($this->gettext('2fa_disabled_success'), 'confirmation');
        rcube_utils::redirect(['_task' => 'settings', '_action' => 'preferences', '_section' => '2fa_section']);
    }

    function settings_page() {
        $rcmail = rcube::get_instance();
        $rcmail->output->send('roundcube_2fa');
    }


    /* ================= TOTP ================= */
    function verify_totp($secret, $code)
    {
        $totp = TOTP::create($secret);
        return $totp->verify($code);
    }

    function get_qr($user, $secret)
    {
        $totp = TOTP::create($secret);
        $totp->setLabel($user);
        $totp->setIssuer('Roundcube');

        $url = $totp->getProvisioningUri();

        // Gera QR code como data-uri
        $result = Builder::create()
            ->data($url)
            ->size(200)
            ->margin(10)
            ->build();

        return $result->getDataUri();
    }

    /* ================= BACKUP ================= */
    function generate_backup_codes()
    {
        $codes = [];
        for ($i = 0; $i < 6; $i++) $codes[] = strval(rand(100000, 999999));
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
