<?php
/**
 * Stub for rcube_config.
 */
class rcube_config
{
    /** @var array<string, mixed> */
    private array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->data) ? $this->data[$key] : $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }
}
