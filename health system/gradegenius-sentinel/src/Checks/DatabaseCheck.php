<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;

final class DatabaseCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Databases & Caches';
    }

    public function category(): string
    {
        return 'database';
    }

    public function run(array $config): array
    {
        $db = $config['db'] ?? [];
        $redisCfg = $config['redis'] ?? null;

        if (empty($db['dsn']) && empty($redisCfg)) {
            return [
                'status'      => 'warn',
                'message'     => 'No database or cache connection configured in config.php',
                'details'     => ['Specify db.dsn or redis settings to enable data-layer health checks.'],
                'remediation' => 'Add your MySQL, PostgreSQL, SQLite, or Redis connection details to config.php',
            ];
        }

        $status = 'ok';
        $details = [];
        $remediations = [];

        // 1. Relational Database check (PDO: MySQL, PostgreSQL, SQLite)
        if (!empty($db['dsn'])) {
            $dsn = (string) $db['dsn'];
            $driver = explode(':', $dsn)[0] ?? 'unknown';
            $t0 = microtime(true);

            try {
                $options = [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_TIMEOUT => 5,
                ];
                $pdo = new \PDO($dsn, $db['user'] ?? null, $db['pass'] ?? null, $options);

                // Basic ping query
                if ($driver === 'sqlite') {
                    $pdo->query('PRAGMA schema_version');
                } else {
                    $pdo->query('SELECT 1');
                }

                $ms = (int) round((microtime(true) - $t0) * 1000);
                $details[] = sprintf('%s connection responding in %d ms', strtoupper($driver), $ms);

                $slowMs = (int) ($db['slow_ms'] ?? 500);
                if ($ms > $slowMs) {
                    $status = $this->worse($status, 'warn');
                    $details[] = "Slow query latency detected ({$ms} ms > {$slowMs} ms limit)";
                    $remediations[] = 'Investigate DB network latency, IO bottlenecks, or connection pool saturation';
                }

                // Verify required tables
                $requiredTables = $db['required_tables'] ?? [];
                foreach ($requiredTables as $table) {
                    try {
                        $clean = str_replace(['`', '"', "'", ';'], '', (string) $table);
                        $pdo->query("SELECT 1 FROM {$clean} LIMIT 1");
                    } catch (\Throwable $te) {
                        $status = 'fail';
                        $details[] = "Missing or unreadable table: {$table}";
                        $remediations[] = 'Run database migrations or verify schema initialization: table missing';
                    }
                }

                // SQLite integrity check if driver is sqlite
                if ($driver === 'sqlite') {
                    $stmt = $pdo->query('PRAGMA integrity_check');
                    $res = $stmt ? $stmt->fetchColumn() : 'unknown';
                    if ($res !== 'ok') {
                        $status = 'fail';
                        $details[] = "SQLite corruption: PRAGMA integrity_check returned '{$res}'";
                        $remediations[] = 'Recover SQLite database from backup or run sqlite3 .recover';
                    }
                }

            } catch (\Throwable $e) {
                $status = 'fail';
                $details[] = "Connection failed to {$driver}: " . $this->scrub($e->getMessage());
                $remediations[] = 'Verify DB host, port, credentials in config.php/.env and ensure database server is running';
            }
        }

        // 2. Redis Cache / Queue check (Socket or Extension)
        if (!empty($redisCfg) && !empty($redisCfg['host'])) {
            $rHost = (string) ($redisCfg['host'] ?? '127.0.0.1');
            $rPort = (int) ($redisCfg['port'] ?? 6379);
            $rTimeout = (float) ($redisCfg['timeout'] ?? 2.0);

            $t0 = microtime(true);
            $socket = @fsockopen($rHost, $rPort, $errno, $errstr, $rTimeout);
            if (!$socket) {
                $status = $this->worse($status, 'warn');
                $details[] = "Redis unreachable at {$rHost}:{$rPort} ({$errstr})";
                $remediations[] = "Start Redis server: 'systemctl status redis' or verify host/port in config";
            } else {
                stream_set_timeout($socket, 2);
                fwrite($socket, "PING\r\n");
                $reply = fgets($socket);
                fclose($socket);
                $rMs = (int) round((microtime(true) - $t0) * 1000);

                if (str_contains((string) $reply, 'PONG')) {
                    $details[] = "Redis responded to PING in {$rMs} ms";
                } else {
                    $status = $this->worse($status, 'warn');
                    $details[] = "Redis ping returned unexpected response: " . trim((string) $reply);
                }
            }
        }

        $message = $status === 'ok'
            ? 'Databases and caches are connected and responsive'
            : ($status === 'warn' ? 'Database or cache warnings detected' : 'Database connectivity failure or missing tables');

        return [
            'status'      => $status,
            'message'     => $message,
            'details'     => $details,
            'remediation' => $remediations ? implode(' | ', $remediations) : null,
        ];
    }

    private function worse(string $a, string $b): string
    {
        $rank = ['ok' => 0, 'warn' => 1, 'fail' => 2];
        return $rank[$b] > $rank[$a] ? $b : $a;
    }

    private function scrub(string $s): string
    {
        return preg_replace('/(password|pwd|pass|secret|token)=\S+/i', '$1=***', $s) ?? $s;
    }
}
