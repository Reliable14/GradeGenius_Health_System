<?php
declare(strict_types=1);

namespace Sentinel;

final class AuthAudit
{
    private const MAX_BYTES = 524288;
    private const KEEP_LINES = 1000;

    public static function record(array $config, string $event, array $server): void
    {
        if (!in_array($event, ['login_failed', 'login_success', 'rate_limited', 'lockout'], true)) {
            error_log('Sentinel auth audit rejected an unknown event type');
            return;
        }

        $dataDir = $config['data_dir'] ?? dirname(__DIR__) . '/data';
        $path = $config['auth_audit_file'] ?? rtrim($dataDir, '/\\') . DIRECTORY_SEPARATOR . 'auth-events.jsonl';
        $directory = dirname($path);
        if (!is_dir($directory) && !@mkdir($directory, 0750, true) && !is_dir($directory)) {
            error_log('Sentinel auth audit could not create its data directory');
            return;
        }

        $remoteIp = (string) ($server['REMOTE_ADDR'] ?? '');
        $ip = filter_var($remoteIp, FILTER_VALIDATE_IP) ? $remoteIp : 'unknown';
        $userAgent = substr((string) ($server['HTTP_USER_AGENT'] ?? 'unknown'), 0, 256);
        $userAgent = preg_replace('/[\x00-\x1F\x7F]/', '', $userAgent) ?: 'unknown';
        $line = json_encode([
            'time' => date('c'),
            'event' => $event,
            'ip' => $ip,
            'user_agent' => $userAgent,
        ], JSON_UNESCAPED_SLASHES);

        if ($line === false) {
            error_log('Sentinel auth audit could not encode an event');
            return;
        }

        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            error_log('Sentinel auth audit could not open its event file');
            return;
        }
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            error_log('Sentinel auth audit could not lock its event file');
            return;
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            if (!@chmod($path, 0600)) {
                error_log('Sentinel auth audit could not restrict event-file permissions');
            }
        }
        $stats = fstat($handle);
        if ($stats !== false && $stats['size'] > self::MAX_BYTES && !self::compact($handle)) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return;
        }

        if (fseek($handle, 0, SEEK_END) !== 0) {
            flock($handle, LOCK_UN);
            fclose($handle);
            error_log('Sentinel auth audit could not seek to the end of its event file');
            return;
        }
        $entry = $line . "\n";
        $written = fwrite($handle, $entry);
        if ($written !== strlen($entry) || !fflush($handle)) {
            error_log('Sentinel auth audit could not persist an event');
        }

        flock($handle, LOCK_UN);
        fclose($handle);
    }

    /** @return array<int, array{time:string,event:string,ip:string,user_agent:string}>|null */
    public static function recent(array $config, int $limit = 100): ?array
    {
        $dataDir = $config['data_dir'] ?? dirname(__DIR__) . '/data';
        $path = $config['auth_audit_file'] ?? rtrim($dataDir, '/\\') . DIRECTORY_SEPARATOR . 'auth-events.jsonl';
        if (!is_file($path)) {
            return [];
        }

        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        if (!flock($handle, LOCK_SH)) {
            fclose($handle);
            return null;
        }
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        if ($contents === false) {
            return null;
        }

        $lines = array_slice(
            array_filter(explode("\n", $contents), static fn(string $line): bool => $line !== ''),
            -max(1, min($limit, self::KEEP_LINES))
        );
        $events = [];
        foreach ($lines as $line) {
            $event = json_decode($line, true);
            if (
                is_array($event)
                && isset($event['time'], $event['event'], $event['ip'], $event['user_agent'])
                && is_string($event['time'])
                && is_string($event['event'])
                && is_string($event['ip'])
                && is_string($event['user_agent'])
            ) {
                $events[] = $event;
            }
        }

        return $events;
    }

    /** @param resource $handle */
    private static function compact($handle): bool
    {
        if (rewind($handle) === false) {
            error_log('Sentinel auth audit could not rewind its event file');
            return false;
        }
        $contents = stream_get_contents($handle);
        if ($contents === false) {
            error_log('Sentinel auth audit could not read its event file for retention');
            return false;
        }

        $lines = array_slice(
            array_filter(explode("\n", $contents), static fn(string $line): bool => $line !== ''),
            -self::KEEP_LINES
        );
        $retained = $lines ? implode("\n", $lines) . "\n" : '';
        if (!ftruncate($handle, 0) || rewind($handle) === false) {
            error_log('Sentinel auth audit could not compact its event file');
            return false;
        }
        if ($retained !== '' && fwrite($handle, $retained) !== strlen($retained)) {
            error_log('Sentinel auth audit could not retain its recent events');
            return false;
        }
        if (!fflush($handle)) {
            error_log('Sentinel auth audit could not flush retained events');
            return false;
        }
        return true;
    }
}
