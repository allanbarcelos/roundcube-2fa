<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

class BackupCodesTest extends TestCase
{
    private roundcube_2fa $plugin;

    protected function setUp(): void
    {
        rcube::reset();
        $this->plugin = new roundcube_2fa();
    }

    public function test_generates_six_codes(): void
    {
        $codes = $this->plugin->generate_backup_codes();

        $this->assertCount(6, $codes);
    }

    public function test_codes_are_six_digit_numeric_strings(): void
    {
        $codes = $this->plugin->generate_backup_codes();

        foreach ($codes as $code) {
            $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
        }
    }

    public function test_codes_are_all_unique(): void
    {
        $codes = $this->plugin->generate_backup_codes();

        $this->assertSame(count($codes), count(array_unique($codes)));
    }

    public function test_consecutive_calls_produce_different_sets(): void
    {
        $first  = $this->plugin->generate_backup_codes();
        $second = $this->plugin->generate_backup_codes();

        // Extremely unlikely to be identical; treat as non-deterministic
        $this->assertNotSame($first, $second);
    }

    public function test_verify_backup_returns_false_for_invalid_code(): void
    {
        $data = [
            'twofa_backup_codes' => json_encode(['111111', '222222']),
            'user_id' => 1,
        ];

        $this->assertFalse($this->plugin->verify_backup('999999', $data));
    }

    public function test_verify_backup_returns_false_for_empty_codes(): void
    {
        $data = [
            'twofa_backup_codes' => json_encode([]),
            'user_id' => 1,
        ];

        $this->assertFalse($this->plugin->verify_backup('111111', $data));
    }

    public function test_verify_backup_returns_false_for_null_codes(): void
    {
        $data = [
            'twofa_backup_codes' => null,
            'user_id' => 1,
        ];

        $this->assertFalse($this->plugin->verify_backup('111111', $data));
    }

    public function test_verify_backup_is_strict_type_comparison(): void
    {
        // Backup codes are stored as strings; loose comparison could match 0 == 'abc'
        $data = [
            'twofa_backup_codes' => json_encode(['123456']),
            'user_id' => 1,
        ];

        // Integer 123456 should NOT match string '123456' via strict comparison
        $this->assertFalse($this->plugin->verify_backup(123456, $data));
    }
}
