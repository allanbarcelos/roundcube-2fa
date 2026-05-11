<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Integration tests using a real in-memory SQLite database.
 * Each test gets an isolated database via setUp().
 */
class PluginTest extends TestCase
{
    private roundcube_2fa $plugin;
    private rcube_db       $db;
    private rcube          $rc;

    protected function setUp(): void
    {
        // Reset singletons so each test starts from a clean slate
        rcube::reset();
        rcube_utils::reset();

        // Inject a fresh in-memory SQLite database
        $this->db = new rcube_db();
        rcube::set_test_db($this->db);

        // Seed the users table
        $this->db->query('CREATE TABLE "users" (user_id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE)');
        $this->db->query('INSERT INTO "users" (user_id, username) VALUES (1, ?)', ['test@example.com']);

        // Configure the Roundcube singleton
        $this->rc            = rcube::get_instance();
        $this->rc->user->ID  = 1;
        $this->rc->user->setUsername('test@example.com');

        // Boot the plugin — this triggers setup_database() which creates roundcube_2fa table
        $this->plugin = new roundcube_2fa();
        $this->plugin->init();
    }

    /* ── Database setup ─────────────────────────────────────────────────── */

    public function test_setup_database_creates_table(): void
    {
        $result = $this->db->query('SELECT 1 FROM "roundcube_2fa" LIMIT 1');

        $this->assertNotFalse($result, 'roundcube_2fa table should exist after init()');
    }

    /* ── get_user_data ──────────────────────────────────────────────────── */

    public function test_get_user_data_returns_row_with_nulls_when_2fa_not_configured(): void
    {
        $data = $this->plugin->get_user_data('test@example.com');

        $this->assertIsArray($data);
        $this->assertEquals(1, $data['user_id']);
        $this->assertNull($data['twofa_secret']);
        $this->assertNull($data['twofa_enabled']);
    }

    public function test_get_user_data_returns_false_for_unknown_user(): void
    {
        $data = $this->plugin->get_user_data('nobody@example.com');

        $this->assertFalse($data);
    }

    /* ── upsert_user ────────────────────────────────────────────────────── */

    public function test_upsert_inserts_record_on_first_call(): void
    {
        $this->plugin->upsert_user([
            'secret'       => 'TESTSECRET123',
            'enabled'      => 1,
            'backup_codes' => json_encode(['111111', '222222']),
        ]);

        $data = $this->plugin->get_user_data('test@example.com');

        $this->assertEquals('TESTSECRET123', $data['twofa_secret']);
        $this->assertEquals(1, $data['twofa_enabled']);
        $this->assertEquals('["111111","222222"]', $data['twofa_backup_codes']);
    }

    public function test_upsert_updates_existing_record(): void
    {
        $this->plugin->upsert_user(['secret' => 'SECRET_V1', 'enabled' => 1, 'backup_codes' => null]);
        $this->plugin->upsert_user(['secret' => 'SECRET_V2', 'enabled' => 1, 'backup_codes' => null]);

        $data = $this->plugin->get_user_data('test@example.com');

        $this->assertEquals('SECRET_V2', $data['twofa_secret']);
    }

    /* ── verify_backup ──────────────────────────────────────────────────── */

    public function test_verify_backup_returns_true_for_valid_code(): void
    {
        $codes = ['111111', '222222', '333333'];
        $this->plugin->upsert_user(['secret' => 'S', 'enabled' => 1, 'backup_codes' => json_encode($codes)]);

        $data   = $this->plugin->get_user_data('test@example.com');
        $result = $this->plugin->verify_backup('222222', $data);

        $this->assertTrue($result);
    }

    public function test_verify_backup_removes_used_code(): void
    {
        $codes = ['111111', '222222', '333333'];
        $this->plugin->upsert_user(['secret' => 'S', 'enabled' => 1, 'backup_codes' => json_encode($codes)]);

        $data = $this->plugin->get_user_data('test@example.com');
        $this->plugin->verify_backup('111111', $data);

        $updated   = $this->plugin->get_user_data('test@example.com');
        $remaining = json_decode($updated['twofa_backup_codes'], true);

        $this->assertNotContains('111111', $remaining);
        $this->assertContains('222222', $remaining);
        $this->assertContains('333333', $remaining);
        $this->assertCount(2, $remaining);
    }

    public function test_verify_backup_reindexes_codes_after_removal(): void
    {
        $codes = ['111111', '222222'];
        $this->plugin->upsert_user(['secret' => 'S', 'enabled' => 1, 'backup_codes' => json_encode($codes)]);

        $data = $this->plugin->get_user_data('test@example.com');
        $this->plugin->verify_backup('111111', $data);

        $updated   = $this->plugin->get_user_data('test@example.com');
        $remaining = json_decode($updated['twofa_backup_codes'], true);

        $this->assertArrayHasKey(0, $remaining, 'Array should be re-indexed from 0');
    }

    public function test_each_backup_code_can_only_be_used_once(): void
    {
        $codes = ['111111'];
        $this->plugin->upsert_user(['secret' => 'S', 'enabled' => 1, 'backup_codes' => json_encode($codes)]);

        $data   = $this->plugin->get_user_data('test@example.com');
        $first  = $this->plugin->verify_backup('111111', $data);

        $data   = $this->plugin->get_user_data('test@example.com');
        $second = $this->plugin->verify_backup('111111', $data);

        $this->assertTrue($first);
        $this->assertFalse($second);
    }

    /* ── disable 2FA ────────────────────────────────────────────────────── */

    public function test_disable_clears_secret_and_codes(): void
    {
        $this->plugin->upsert_user(['secret' => 'SECRET', 'enabled' => 1, 'backup_codes' => '["111111"]']);
        $this->plugin->upsert_user(['secret' => null, 'enabled' => 0, 'backup_codes' => null]);

        $data = $this->plugin->get_user_data('test@example.com');

        $this->assertEquals(0, $data['twofa_enabled']);
        $this->assertNull($data['twofa_secret']);
        $this->assertNull($data['twofa_backup_codes']);
    }

    /* ── settings_page output ───────────────────────────────────────────── */

    public function test_settings_page_assigns_false_when_2fa_not_enabled(): void
    {
        $this->plugin->settings_page();

        $this->assertFalse($this->rc->output->env['two_fa_enabled']);
        $this->assertSame('settings_page', $this->rc->output->last_template);
    }

    public function test_settings_page_assigns_true_when_2fa_enabled(): void
    {
        $this->plugin->upsert_user(['secret' => 'S', 'enabled' => 1, 'backup_codes' => null]);

        $this->plugin->settings_page();

        $this->assertTrue($this->rc->output->env['two_fa_enabled']);
    }

    /* ── verify_and_enable ──────────────────────────────────────────────── */

    public function test_verify_and_enable_rejects_invalid_csrf_token(): void
    {
        rcube_utils::set_token_valid(false);
        $_SESSION['2fa_tmp_secret'] = 'SECRET';

        $this->plugin->verify_and_enable();

        $data = $this->plugin->get_user_data('test@example.com');
        $this->assertNull($data['twofa_enabled'], '2FA must not be enabled on CSRF failure');

        $errors = array_filter($this->rc->output->messages, fn($m) => $m['type'] === 'error');
        $this->assertNotEmpty($errors);
    }

    public function test_verify_and_enable_rejects_wrong_totp_code(): void
    {
        $secret                     = $this->plugin->generate_secret();
        $_SESSION['2fa_tmp_secret'] = $secret;
        $_POST['_code']             = '000000';

        $this->plugin->verify_and_enable();

        $data = $this->plugin->get_user_data('test@example.com');
        $this->assertNull($data['twofa_enabled']);
    }

    public function test_verify_and_enable_stores_2fa_on_valid_code(): void
    {
        $secret                     = $this->plugin->generate_secret();
        $_SESSION['2fa_tmp_secret'] = $secret;
        $_POST['_code']             = \OTPHP\TOTP::create($secret)->now();

        $this->plugin->verify_and_enable();

        $data = $this->plugin->get_user_data('test@example.com');
        $this->assertEquals(1, $data['twofa_enabled']);
        $this->assertEquals($secret, $data['twofa_secret']);
    }

    public function test_verify_and_enable_exposes_backup_codes_after_success(): void
    {
        $secret                     = $this->plugin->generate_secret();
        $_SESSION['2fa_tmp_secret'] = $secret;
        $_POST['_code']             = \OTPHP\TOTP::create($secret)->now();

        $this->plugin->verify_and_enable();

        $this->assertArrayHasKey('two_fa_backup_codes', $this->rc->output->env);
        $this->assertCount(6, $this->rc->output->env['two_fa_backup_codes']);
    }

    protected function tearDown(): void
    {
        // Clear superglobals mutated by tests
        $_POST    = [];
        $_SESSION = [];
        rcube_utils::reset();
    }
}
