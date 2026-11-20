<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\AuthAudit;
use Sentinel\Contracts\CheckInterface;

final class DashboardAuthCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Dashboard Login Attempts';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        $events = AuthAudit::recent($config, 500);
        if ($events === null) {
            return [
                'status' => 'warn',
                'message' => 'Unable to read the dashboard authentication audit log',
                'details' => ['Login attempt auditing may be unavailable because the event file cannot be read.'],
                'remediation' => 'Check data_dir ownership and permissions; ensure it is outside the public web root.',
            ];
        }

        $windowMinutes = max(1, (int) ($config['auth_audit_window_minutes'] ?? 60));
        $windowStart = time() - ($windowMinutes * 60);
        $failuresByIp = [];
        $recent = [];

        foreach (array_reverse($events) as $event) {
            $timestamp = strtotime($event['time']);
            if ($timestamp === false) {
                continue;
            }
            if ($timestamp >= $windowStart && in_array($event['event'], ['login_failed', 'rate_limited'], true)) {
                $ip = $event['ip'];
                $failuresByIp[$ip] = ($failuresByIp[$ip] ?? 0) + 1;
            }
            if (count($recent) < 12) {
                $recent[] = sprintf(
                    '%s - %s from %s (agent: %s)',
                    date('Y-m-d H:i:s', $timestamp),
                    str_replace('_', ' ', $event['event']),
                    $event['ip'],
                    substr($event['user_agent'], 0, 120)
                );
            }
        }

        arsort($failuresByIp);
        $failures = array_sum($failuresByIp);
        $topIpCount = $failuresByIp ? reset($failuresByIp) : 0;
        $warnLimit = max(1, (int) ($config['thresholds']['auth_ip_warn'] ?? 5));
        $failLimit = max($warnLimit, (int) ($config['thresholds']['auth_ip_fail'] ?? 20));
        $status = $topIpCount >= $failLimit ? 'fail' : ($topIpCount >= $warnLimit ? 'warn' : 'ok');
        $details = [
            "Failed or rate-limited attempts in the last {$windowMinutes} minutes: {$failures}",
            'Unique source IPs with failed attempts: ' . count($failuresByIp),
            'Passwords are never stored; audit records contain time, source IP, event type, and a capped user-agent string.',
        ];

        foreach (array_slice($failuresByIp, 0, 5, true) as $ip => $count) {
            $details[] = "Source {$ip}: {$count} failed or rate-limited attempt(s) in the audit window";
        }
        foreach ($recent as $entry) {
            $details[] = 'Recent event: ' . $entry;
        }

        $remediation = $status === 'ok' ? null
            : 'Verify the source IP in trusted proxy/web-server logs, enable MFA and edge rate limits, and block only after confirming it is not a shared or trusted address.';
        $message = $status === 'fail'
            ? "Repeated login failures from one IP ({$topIpCount} in {$windowMinutes}m)"
            : ($status === 'warn'
                ? "Elevated login failures from one IP ({$topIpCount} in {$windowMinutes}m)"
                : ($failures ? "{$failures} failed dashboard sign-in attempt(s) recorded" : 'No recent failed dashboard sign-ins'));

        return [
            'status' => $status,
            'message' => $message,
            'details' => $details,
            'remediation' => $remediation,
        ];
    }
}
