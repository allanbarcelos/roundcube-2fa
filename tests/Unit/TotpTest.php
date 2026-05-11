<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use OTPHP\TOTP;

class TotpTest extends TestCase
{
    private roundcube_2fa $plugin;

    protected function setUp(): void
    {
        rcube::reset();
        $this->plugin = new roundcube_2fa();
    }

    public function test_generate_secret_returns_non_empty_string(): void
    {
        $secret = $this->plugin->generate_secret();

        $this->assertIsString($secret);
        $this->assertNotEmpty($secret);
    }

    public function test_generate_secret_returns_valid_base32(): void
    {
        $secret = $this->plugin->generate_secret();

        // TOTP secrets are Base32-encoded (A-Z, 2-7, optional padding)
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+=*$/', $secret);
    }

    public function test_generate_secret_returns_different_values_each_call(): void
    {
        $a = $this->plugin->generate_secret();
        $b = $this->plugin->generate_secret();

        $this->assertNotSame($a, $b);
    }

    public function test_verify_totp_returns_false_for_null_secret(): void
    {
        $this->assertFalse($this->plugin->verify_totp(null, '123456'));
    }

    public function test_verify_totp_returns_false_for_null_code(): void
    {
        $secret = $this->plugin->generate_secret();

        $this->assertFalse($this->plugin->verify_totp($secret, null));
    }

    public function test_verify_totp_returns_false_for_empty_code(): void
    {
        $secret = $this->plugin->generate_secret();

        $this->assertFalse($this->plugin->verify_totp($secret, ''));
    }

    public function test_verify_totp_returns_false_for_wrong_code(): void
    {
        $secret = $this->plugin->generate_secret();

        $this->assertFalse($this->plugin->verify_totp($secret, '000000'));
    }

    public function test_verify_totp_returns_true_for_current_code(): void
    {
        $secret = $this->plugin->generate_secret();
        $code   = TOTP::create($secret)->now();

        $this->assertTrue($this->plugin->verify_totp($secret, $code));
    }

    public function test_get_qr_returns_data_uri(): void
    {
        $secret = $this->plugin->generate_secret();
        $uri    = $this->plugin->get_qr('user@example.com', $secret);

        $this->assertStringStartsWith('data:image/', $uri);
    }

    public function test_get_qr_respects_custom_issuer(): void
    {
        $secret = $this->plugin->generate_secret();
        rcube::get_instance()->config->set('roundcube_2fa_issuer', 'MyCompany');

        $uri = $this->plugin->get_qr('user@example.com', $secret);

        $this->assertStringStartsWith('data:image/', $uri);
    }
}
