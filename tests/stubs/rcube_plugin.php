<?php
/**
 * Minimal stub for rcube_plugin — provides the abstract base the plugin extends.
 */
abstract class rcube_plugin
{
    public $task;

    public function __construct($api = null) {}

    abstract public function init();

    public function load_config(): void {}
    public function add_texts(string $dir): void {}
    public function add_hook(string $hook, callable $callback): void {}
    public function register_action(string $action, callable $callback): void {}
    public function gettext(string $key): string { return $key; }
}
