<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;

final class ProductionReadinessCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Production Readiness';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        $environment = strtolower((string) ($config['environment'] ?? 'production'));
        if ($environment === 'demo') {
            return [
                'status' => 'ok',
                'message' => 'Demo environment; production-only recommendations are not enforced',
                'details' => ['Demo incident simulations are enabled without changing live services or audit records.'],
                'remediation' => null,
            ];
        }

        $details = [];
        $recommendations = [];
        $status = 'ok';
        $passwordHash = (string) ($config['dashboard_password_hash'] ?? '');
        if ($passwordHash === '' || (password_get_info($passwordHash)['algoName'] ?? 'unknown') === 'unknown') {
            $status = 'fail';
            $details[] = 'Dashboard password hash is missing or invalid.';
            $recommendations[] = 'Generate a password hash with "php cli.php make-password" and set SENTINEL_PASSWORD_HASH in the server environment.';
        } else {
            $details[] = 'Dashboard password hash is configured.';
        }

        $appUrl = (string) ($config['app_url'] ?? '');
        if (filter_var($appUrl, FILTER_VALIDATE_URL) === false || strtolower((string) parse_url($appUrl, PHP_URL_SCHEME)) !== 'https') {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'Application URL is not configured as a valid HTTPS URL.';
            $recommendations[] = 'Set app_url to the HTTPS endpoint technicians should verify.';
        } else {
            $details[] = 'Application URL uses HTTPS.';
        }

        if (trim((string) ($config['learning_health_url'] ?? '')) === '') {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'Learning health URL is not configured.';
            $recommendations[] = 'Set SENTINEL_LEARNING_HEALTH_URL when this deployment has a learning API or worker health route.';
        } else {
            $details[] = 'Learning health endpoint is configured.';
        }

        if (empty($config['dashboard_allowed_ips'])) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'Dashboard IP allowlist is empty.';
            $recommendations[] = 'Restrict dashboard access through a trusted VPN, reverse proxy, or dashboard_allowed_ips policy.';
        } else {
            $details[] = 'Dashboard IP allowlist contains ' . count($config['dashboard_allowed_ips']) . ' configured address(es).';
        }

        $publicRoot = realpath(dirname(__DIR__, 2) . '/public');
        $dataDirectory = (string) ($config['data_dir'] ?? '');
        $resolvedDataDirectory = $dataDirectory !== '' ? realpath($dataDirectory) : false;
        if ($publicRoot !== false && $resolvedDataDirectory !== false && self::isWithin($resolvedDataDirectory, $publicRoot)) {
            $status = 'fail';
            $details[] = 'data_dir resolves inside the public web root.';
            $recommendations[] = 'Move data_dir outside the web root and deny web access to reports, audit events, and baselines.';
        } elseif ($resolvedDataDirectory === false || !is_writable($resolvedDataDirectory)) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'data_dir does not resolve to a writable directory.';
            $recommendations[] = 'Create data_dir outside the public web root and grant the Sentinel process the minimum required write access.';
        } else {
            $details[] = 'data_dir resolves outside the public web root and is writable.';
        }

        $auditPath = (string) ($config['auth_audit_file'] ?? '');
        if ($auditPath !== '' && $publicRoot !== false) {
            $auditLocation = realpath($auditPath) ?: realpath(dirname($auditPath));
            if ($auditLocation !== false && self::isWithin($auditLocation, $publicRoot)) {
                $status = 'fail';
                $details[] = 'The configured authentication audit file or its parent directory is inside the public web root.';
                $recommendations[] = 'Move auth_audit_file outside the public web root.';
            }
        }

        $logFiles = $config['log_files'] ?? [];
        $missingLogs = array_values(array_filter($logFiles, static fn($path): bool => !is_string($path) || !is_readable($path)));
        if (!$logFiles) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'No application log files are configured.';
            $recommendations[] = 'Set log_files to the relevant application and worker logs when available.';
        } elseif ($missingLogs) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = count($missingLogs) . ' configured application log file(s) are missing or unreadable.';
            $recommendations[] = 'Verify log_files paths and grant the Sentinel process read-only access to the intended logs.';
        } else {
            $details[] = count($logFiles) . ' configured application log file(s) are readable.';
        }

        if (PHP_OS_FAMILY === 'Linux' && empty($config['monitored_services'])) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'No Linux system services are configured for monitoring.';
            $recommendations[] = 'Set monitored_services to the application services and workers this host is expected to run.';
        }

        $alerts = $config['alerts'] ?? [];
        $emails = is_array($alerts['email'] ?? null)
            ? array_filter($alerts['email'], static fn($email): bool => is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false)
            : [];
        $webhook = (string) ($alerts['webhook'] ?? '');
        $validWebhook = $webhook !== ''
            && filter_var($webhook, FILTER_VALIDATE_URL) !== false
            && strtolower((string) parse_url($webhook, PHP_URL_SCHEME)) === 'https';
        if (!$emails && !$validWebhook) {
            $status = $status === 'fail' ? 'fail' : 'warn';
            $details[] = 'No valid email or HTTPS webhook alert destination is configured.';
            $recommendations[] = 'Configure at least one monitored alert destination and test delivery before relying on notifications.';
        } else {
            $details[] = 'At least one valid alert destination is configured.';
            if ($webhook !== '' && !$validWebhook) {
                $status = $status === 'fail' ? 'fail' : 'warn';
                $details[] = 'The configured alert webhook is not a valid HTTPS URL.';
                $recommendations[] = 'Use an HTTPS webhook endpoint and keep its secret in SENTINEL_WEBHOOK.';
            }
        }

        $recommendations[] = 'Keep the API token, database credentials, and webhook secrets in environment variables; never commit them to config.php.';
        return [
            'status' => $status,
            'message' => $status === 'fail' ? 'Production configuration has a critical readiness issue'
                : ($status === 'warn' ? 'Review production configuration recommendations' : 'Core production configuration checks passed'),
            'details' => $details,
            'remediation' => $recommendations ? implode(' | ', array_unique($recommendations)) : null,
        ];
    }

    private static function isWithin(string $path, string $parent): bool
    {
        $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
        $parent = rtrim(str_replace('\\', '/', $parent), '/') . '/';
        if (DIRECTORY_SEPARATOR === '\\') {
            $path = strtolower($path);
            $parent = strtolower($parent);
        }
        return str_starts_with($path, $parent);
    }
}
