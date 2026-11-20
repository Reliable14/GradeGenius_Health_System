<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class SecurityCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Network & Web Security';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        $status = 'ok';
        $details = [];
        $remediations = [];

        $url = rtrim($config['app_url'] ?? '', '/');
        $root = realpath($config['app_root'] ?? '') ?: ($config['app_root'] ?? '');

        // 1. HTTP Endpoint & Security Headers (if URL provided)
        if ($url !== '' && function_exists('curl_init')) {
            [$code, $headers, $ms] = $this->http($url . '/');

            if ($code === 0) {
                $status = 'fail';
                $details[] = "Application URL is unreachable: {$url}";
                $remediations[] = 'Verify web server (Nginx/Apache/Caddy/Node) is running and DNS/ports are open';
            } else {
                $details[] = "Endpoint: HTTP {$code} in {$ms} ms";
                if ($code >= 500) {
                    $status = 'fail';
                    $remediations[] = 'Web server returning 5xx Internal Server Error: check web server error logs';
                } elseif ($code >= 400) {
                    $status = $this->worse($status, 'warn');
                }

                $slowThreshold = $config['thresholds']['http_slow_ms'] ?? 2000;
                if ($ms > $slowThreshold) {
                    $status = $this->worse($status, 'warn');
                    $details[] = "High HTTP response time ({$ms} ms > {$slowThreshold} ms)";
                    $remediations[] = 'Enable caching or optimize web server worker pools';
                }

                // Security headers audit
                $secHeaders = [
                    'strict-transport-security' => 'Strict-Transport-Security (HSTS)',
                    'x-frame-options'           => 'X-Frame-Options (Clickjacking defense)',
                    'x-content-type-options'    => 'X-Content-Type-Options (MIME sniffing defense)',
                    'content-security-policy'   => 'Content-Security-Policy (CSP)',
                ];

                foreach ($secHeaders as $header => $label) {
                    if (stripos($headers, $header . ':') === false) {
                        $status = $this->worse($status, 'warn');
                        $details[] = "Missing recommended security header: {$label}";
                    }
                }

                // Sensitive exposed paths check
                $sensitivePaths = [
                    '/.env'          => 'Environment secret file (.env)',
                    '/.git/config'   => 'Git repository metadata (.git)',
                    '/phpinfo.php'   => 'PHP diagnostics page (phpinfo.php)',
                    '/composer.json' => 'Composer package manifest',
                    '/backup.zip'    => 'Raw backup archive',
                    '/dump.sql'      => 'Database export dump',
                ];

                foreach ($sensitivePaths as $path => $desc) {
                    [$c] = $this->http($url . $path);
                    if ($c === 200) {
                        $status = 'fail';
                        $details[] = "CRITICAL EXPOSURE: {$desc} is publicly accessible at {$url}{$path}";
                        $remediations[] = "Block web access to {$path} in web server config (e.g. Nginx: location ~ /\\.(?!well-known) { deny all; })";
                    }
                }

                // SSL Certificate expiration
                if (str_starts_with($url, 'https://')) {
                    $host = (string) parse_url($url, PHP_URL_HOST);
                    $days = $this->sslDaysLeft($host);
                    if ($days === null) {
                        $status = $this->worse($status, 'warn');
                        $details[] = "Could not retrieve SSL certificate for {$host}";
                    } else {
                        $details[] = "SSL Certificate expires in {$days} day(s)";
                        if ($days < 7) {
                            $status = 'fail';
                            $details[] = 'CRITICAL: SSL certificate expires in less than 7 days!';
                            $remediations[] = 'Renew SSL certificate immediately: run "certbot renew"';
                        } elseif ($days < 21) {
                            $status = $this->worse($status, 'warn');
                            $remediations[] = 'Schedule SSL renewal within 21 days';
                        }
                    }
                } else {
                    $status = $this->worse($status, 'warn');
                    $details[] = 'Site is not served over HTTPS';
                    $remediations[] = 'Configure TLS/SSL certificate with Let\'s Encrypt / Certbot';
                }
            }
        }

        // 2. File permissions (POSIX-specific: avoid Windows permission masking false positives)
        if ($root && is_dir($root) && !OsHelper::isWindows()) {
            $envFile = $root . '/.env';
            if (is_file($envFile)) {
                $perms = fileperms($envFile);
                if ($perms !== false && ($perms & 0004)) {
                    $status = 'fail';
                    $details[] = '.env file is world-readable';
                    $remediations[] = 'Harden .env permissions: run "chmod 640 .env"';
                }
            }
        }

        $message = $status === 'ok'
            ? 'Network, web endpoints, and SSL are hardened'
            : ($status === 'warn' ? 'Security posture recommendations' : 'Critical security vulnerabilities or exposures detected');

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

    private function http(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => 'DevSentinel/2.0',
        ]);
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms   = (int) round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
        $hs   = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        return [$resp === false ? 0 : $code, $resp === false ? '' : substr((string) $resp, 0, $hs), $ms];
    }

    private function sslDaysLeft(string $host): ?int
    {
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'SNI_enabled' => true, 'peer_name' => $host]]);
        $c = @stream_socket_client("ssl://{$host}:443", $en, $es, 5, STREAM_CLIENT_CONNECT, $ctx);
        if (!$c) return null;
        $cert = stream_context_get_params($c)['options']['ssl']['peer_certificate'] ?? null;
        $info = $cert ? openssl_x509_parse($cert) : null;
        return $info ? (int) floor(($info['validTo_time_t'] - time()) / 86400) : null;
    }
}
