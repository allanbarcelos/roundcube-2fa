<?php
/**
 * Stub for rcube_user.
 */
class rcube_user
{
    public int $ID = 1;

    private string $username = 'test@example.com';

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): void
    {
        $this->username = $username;
    }
}
