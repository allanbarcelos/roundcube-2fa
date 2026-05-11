<?php
/**
 * Stub for rcube_db backed by an in-memory SQLite database.
 *
 * Mirrors the Roundcube DB API used by the plugin:
 *   - query($sql, $params)  — $params may be an array or spread args
 *   - fetch_assoc($result)
 *   - is_error($result)
 *   - table_name($table, $quoted)
 */
class rcube_db
{
    public string $db_provider = 'sqlite';

    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
    }

    /**
     * Execute a query. Accepts params as a single array or as spread arguments,
     * matching Roundcube's rcube_db::query() behaviour.
     *
     * @return \PDOStatement|false
     */
    public function query(string $sql, ...$args)
    {
        $params = (count($args) === 1 && is_array($args[0])) ? $args[0] : $args;

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (\PDOException $e) {
            return false;
        }
    }

    /** @return array<string,mixed>|false */
    public function fetch_assoc($result)
    {
        if ($result === false) return false;
        $row = $result->fetch(\PDO::FETCH_ASSOC);
        return $row !== false ? $row : false;
    }

    public function is_error($result): bool
    {
        return $result === false;
    }

    public function table_name(string $table, bool $quoted = false): string
    {
        return $quoted ? '"' . $table . '"' : $table;
    }
}
