<?php
/**
 * Stub for rcube / rcmail — injectable singleton used throughout the plugin.
 */
class rcube
{
    private static ?self $instance = null;
    private static ?rcube_db $test_db = null;

    public rcube_output $output;
    public rcube_config  $config;
    public rcube_user    $user;

    private function __construct()
    {
        $this->output = new rcube_output();
        $this->config = new rcube_config();
        $this->user   = new rcube_user();
    }

    public static function get_instance(): static
    {
        if (self::$instance === null) {
            self::$instance = new static();
        }
        return self::$instance;
    }

    /** Inject a specific DB for the current test. */
    public static function set_test_db(rcube_db $db): void
    {
        self::$test_db = $db;
    }

    /** Reset singleton and injected DB between tests. */
    public static function reset(): void
    {
        self::$instance = null;
        self::$test_db  = null;
    }

    public function get_dbh(): rcube_db
    {
        return self::$test_db ?? new rcube_db();
    }

    public function get_user_name(): string
    {
        return $this->user->getUsername();
    }

    public function overwrite_action(string $action): void
    {
        $this->output->overwrite_action($action);
    }
}

/**
 * rcmail is an alias for rcube in the Roundcube codebase.
 */
class rcmail extends rcube {}
