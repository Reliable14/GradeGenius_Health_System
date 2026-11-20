<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;

final class LogCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Logs & Error Diagnostics';
    }

    public function category(): string
    {
        return 'logs';
    }

    public function run(array $config): array
    {
        $logFiles = $config['log_files'] ?? [];
        $windowMinutes = (int) ($config['log_window_minutes'] ?? 60);
        $thresholds = $config['thresholds'] ?? [];
        $limitFatal = (int) ($thresholds['log_fatal_fail'] ?? 10);
        $limitWarn  = (int) ($thresholds['log_warn_warn'] ?? 50);
        $limitAuth  = (int) ($thresholds['log_auth_fail'] ?? 50);

        $win = time() - ($windowMinutes * 60);
        $fatal = 0;
        $warn = 0;
        $auth = 0;
        $samples = [];
        $authByIp = [];
        $readableLogs = [];

        foreach ($logFiles as $log) {
            if (!is_file($log) || !is_readable($log)) continue;
            $readableLogs[] = basename($log);

            foreach ($this->tail($log, 512 * 1024) as $line) {
                if (preg_match('/^\[([^\]]+)\]/', $line, $m)) {
                    $ts = strtotime($m[1]);
                    if ($ts !== false && $ts < $win) continue;
                }

                if (preg_match('/Fatal error|Uncaught|Stack trace|Parse error|SQLSTATE|Exception:/i', $line)) {
                    $fatal++;
                    if (count($samples) < 6) {
                        $samples[] = 'ERROR: ' . $this->safeSample($line);
                    }
                } elseif (preg_match('/Warning|Notice|Deprecated/i', $line)) {
                    $warn++;
                }

                if (preg_match('/failed login|login failed|login_failure|login_failed|authentication failed|invalid credentials|invalid password|wrong password|401 Unauthorized/i', $line)) {
                    $auth++;
                    $ip = $this->extractIp($line);
                    if ($ip !== null) {
                        $authByIp[$ip] = ($authByIp[$ip] ?? 0) + 1;
                    }
                    if (count($samples) < 8) {
                        $samples[] = $ip === null
                            ? 'AUTH FAIL: login failure detected; no source IP was present in the log'
                            : "AUTH FAIL: login failure detected from {$ip}";
                    }
                }
            }
        }

        if (empty($readableLogs)) {
            return [
                'status'      => 'warn',
                'message'     => 'No accessible log files found in log_files list',
                'details'     => ['Configured paths could not be opened for reading.'],
                'remediation' => 'Verify log_files paths in config.php and ensure read permissions for the web/CLI user',
            ];
        }

        $details = [
            sprintf('Active logs analyzed (%d): %s', count($readableLogs), implode(', ', $readableLogs)),
            "Past {$windowMinutes} min: {$fatal} fatal error(s), {$warn} warning(s), {$auth} failed auth attempt(s)",
        ];

        foreach ($samples as $s) {
            $details[] = '  ' . $s;
        }

        arsort($authByIp);
        $maxAuthFromIp = $authByIp ? reset($authByIp) : 0;
        foreach (array_slice($authByIp, 0, 5, true) as $ip => $attempts) {
            $details[] = "Failed logins from {$ip}: {$attempts} in the last {$windowMinutes} minutes";
        }

        $status = 'ok';
        $remediations = [];
        $authIpWarn = (int) ($thresholds['auth_ip_warn'] ?? 5);
        $authIpFail = (int) ($thresholds['auth_ip_fail'] ?? 20);

        if ($fatal >= $limitFatal || $auth >= $limitAuth || $maxAuthFromIp >= $authIpFail) {
            $status = 'fail';
            if ($fatal >= $limitFatal) {
                $remediations[] = 'High volume of application exceptions: inspect live stream with "tail -f <log_path>"';
            }
            if ($auth >= $limitAuth || $maxAuthFromIp >= $authIpFail) {
                $remediations[] = 'Potential brute-force activity: verify source IPs and enable Fail2ban or edge rate-limiting on login endpoints';
            }
        } elseif ($fatal > 0 || $warn >= $limitWarn || $auth >= ($thresholds['log_auth_warn'] ?? 15) || $maxAuthFromIp >= $authIpWarn) {
            $status = 'warn';
            if ($fatal > 0) $remediations[] = 'Review recent stack traces in application logs';
            if ($maxAuthFromIp >= $authIpWarn) {
                $remediations[] = 'Review the source IP against trusted proxy logs and enable edge rate limiting; do not block shared addresses without verification';
            }
        }

        $message = $status === 'ok'
            ? "Logs healthy (0 fatal errors in past {$windowMinutes}m)"
            : "{$fatal} fatal exception(s) & {$auth} failed auth event(s) in last {$windowMinutes}m";

        return [
            'status'      => $status,
            'message'     => $message,
            'details'     => $details,
            'remediation' => $remediations ? implode(' | ', $remediations) : null,
        ];
    }

    /** @return string[] */
    private function tail(string $file, int $bytes): array
    {
        $size = filesize($file);
        if ($size === false || $size === 0) return [];
        $fh = @fopen($file, 'rb');
        if (!$fh) return [];
        if ($size > $bytes) fseek($fh, -$bytes, SEEK_END);
        $data = stream_get_contents($fh);
        fclose($fh);
        return explode("\n", (string) $data);
    }

    private function extractIp(string $line): ?string
    {
        preg_match_all(
            '/(?<![A-F0-9:.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|(?<![A-F0-9:])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}(?![A-F0-9:])/i',
            $line,
            $matches
        );
        foreach ($matches[0] ?? [] as $candidate) {
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }
        return null;
    }

    private function safeSample(string $line): string
    {
        $line = preg_replace(
            '/(["\']?(?:password|passwd|pwd|token|secret|authorization)["\']?\s*[:=]\s*)(?:"[^"]*"|\'[^\']*\'|[^\s,;}]+)/i',
            '$1[REDACTED]',
            $line
        ) ?? '[log sample omitted]';
        $line = preg_replace('/(authorization\s*[:=]\s*Bearer\s+)\S+/i', '$1[REDACTED]', $line) ?? '[log sample omitted]';
        $line = preg_replace('/(--?(?:password|passwd|pwd)\s+)(?:"[^"]*"|\'[^\']*\'|\S+)/i', '$1[REDACTED]', $line) ?? '[log sample omitted]';
        $line = preg_replace('/\b(password|passwd|pwd)\s+(?:"[^"]*"|\'[^\']*\'|\S+)/i', '$1 [REDACTED]', $line) ?? '[log sample omitted]';
        return substr(trim($line), 0, 180);
    }
}
