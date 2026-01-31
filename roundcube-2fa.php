<?php
namespace TwoFactor;

require_once __DIR__ . '/vendor/autoload.php';

use rcube;
use rcube_plugin;
use Endroid\QrCode\Builder\Builder;
use OTPHP\TOTP;

class roundcube_2fa extends rcube_plugin
{
    public $task = 'login|settings';

    function init()
    {
        $this->load_config();
        $this->add_texts('../locale/');
        $this->add_hook('authenticate', [$this, 'check_2fa']);
        $this->register_action('plugin.roundcube_2fa-setup', [$this, 'setup']);
        $this->register_action('plugin.roundcube_2fa-disable', [$this, 'disable']);

        $this->task = 'login|settings';
        $this->register_action('plugin.roundcube_2fa-settings', [$this, 'settings_page']);

        $this->setup_database();
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
        rcube::get_instance()->output->send('roundcube_2fa.roundcube_2fa');
    }

    /* ================= SETUP ================= */
    function setup()
    {
        $rcmail = rcube::get_instance();
        $secret = $this->generate_secret();
        $_SESSION['2fa_tmp_secret'] = $secret;

        $qr = $this->get_qr($rcmail->get_user_name(), $secret);

        $rcmail->output->assign('qr', $qr);
        $rcmail->output->send('roundcube_2fa.setup');
    }

    function disable()
    {
        $this->update_user([
            'twofa_enabled' => 0,
            'twofa_secret' => null,
            'twofa_backup_codes' => null
        ]);
        rcube::get_instance()->output->send('roundcube_2fa.disable');
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
        $db = rcube::get_instance()->get_dbh();
        return $db->fetchAssoc("SELECT * FROM users WHERE username=?", [$user]);
    }

    function update_user($fields)
    {
        $db = rcube::get_instance()->get_dbh();
        $user = rcube::get_instance()->get_user_name();
        foreach ($fields as $k => $v) {
            $db->query("UPDATE users SET $k=? WHERE username=?", [$v, $user]);
        }
    }

    function generate_secret()
    {
        $totp = TOTP::create();
        return $totp->getSecret();
    }
    
    /* ================= DATABASE SETUP ================= */

    private function setup_database()
    {
        $rcmail = \rcube::get_instance();
        $dbh = $rcmail->get_dbh();

        $columns = [
            'twofa_secret' => "VARCHAR(64)",
            'twofa_enabled' => "TINYINT(1) DEFAULT 0",
            'twofa_backup_codes' => "TEXT"
        ];

        $table = "users";

        foreach ($columns as $col => $type) {
            $exists = $dbh->fetchOne("SHOW COLUMNS FROM `$table` LIKE ?", [$col]);
            if (!$exists) {
                $dbh->query("ALTER TABLE `$table` ADD COLUMN `$col` $type");
            }
        }
    }

}
