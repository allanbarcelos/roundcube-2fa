<?php
/**
 * Stub for rcube_utils — static utility class used by the plugin.
 */
class rcube_utils
{
    public const INPUT_GET  = 1;
    public const INPUT_POST = 2;
    public const INPUT_GPC  = 3;

    private static bool $token_valid = true;

    public static function get_input_value(string $key, int $source = self::INPUT_GPC): mixed
    {
        return match ($source) {
            self::INPUT_POST => $_POST[$key] ?? null,
            self::INPUT_GET  => $_GET[$key]  ?? null,
            default          => $_REQUEST[$key] ?? null,
        };
    }

    public static function check_request_token(?string $token = null): bool
    {
        return self::$token_valid;
    }

    /** Control CSRF token validity in tests. */
    public static function set_token_valid(bool $valid): void
    {
        self::$token_valid = $valid;
    }

    public static function reset(): void
    {
        self::$token_valid = true;
    }
}
