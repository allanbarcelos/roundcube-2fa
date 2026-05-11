<?php
/**
 * Stub for rcube_output — captures calls made by the plugin so tests can assert on them.
 */
class rcube_output
{
    /** @var array<int, array{text: string, type: string}> */
    public array $messages = [];

    /** @var array<string, mixed> */
    public array $env = [];

    public ?string $last_template = null;

    public ?string $last_action = null;

    public function show_message(string $text, string $type = 'notice'): void
    {
        $this->messages[] = ['text' => $text, 'type' => $type];
    }

    public function assign(string $key, mixed $value): void
    {
        $this->env[$key] = $value;
    }

    public function send(string $template): void
    {
        $this->last_template = $template;
    }

    public function overwrite_action(string $action): void
    {
        $this->last_action = $action;
    }
}
