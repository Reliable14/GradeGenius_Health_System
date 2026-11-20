<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;

final class LearningHealthCheck implements CheckInterface
{
    private const MAX_BODY_BYTES = 16384;

    public function name(): string
    {
        return 'Learning Service Health';
    }

    public function category(): string
    {
        return 'devops';
    }

    public function run(array $config): array
    {
        $startedAt = microtime(true);
        $result = $this->probe($config);
        $durationMs = (int) round((microtime(true) - $startedAt) * 1000);
        $historyResult = $this->recordHistory($config, $result, $durationMs);
        $result['details'][] = "Health probe response time: {$durationMs} ms";
        if ($historyResult === null) {
            $result['details'][] = 'Health history could not be saved; verify data_dir permissions.';
        } elseif ($historyResult['transition'] !== '') {
            $result['details'][] = 'Health state transition: ' . $historyResult['transition'];
        }
        return $result;
    }

    /** @return array<int,array{time:string,status:string,ms:int,message:string,transition:string}>|null */
    public static function history(array $config, int $limit = 20): ?array
    {
        $path = rtrim((string) ($config['data_dir'] ?? dirname(__DIR__, 2) . '/data'), '/\\')
            . DIRECTORY_SEPARATOR . 'learning-health.jsonl';
        if (!is_file($path)) {
            return [];
        }
        $contents = @file_get_contents($path);
        if ($contents === false) {
            return null;
        }
        $events = [];
        foreach (array_slice(explode("\n", $contents), -max(1, min($limit, 1000))) as $line) {
            $event = json_decode($line, true);
            if (
                is_array($event)
                && isset($event['time'], $event['status'], $event['ms'], $event['message'], $event['transition'])
                && is_string($event['time'])
                && is_string($event['status'])
                && is_numeric($event['ms'])
                && is_string($event['message'])
                && is_string($event['transition'])
            ) {
                $events[] = $event;
            }
        }
        return $events;
    }

    private function recordHistory(array $config, array $result, int $durationMs): ?array
    {
        $directory = (string) ($config['data_dir'] ?? dirname(__DIR__, 2) . '/data');
        if (!is_dir($directory) && !@mkdir($directory, 0750, true) && !is_dir($directory)) {
            return null;
        }
        $path = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . 'learning-health.jsonl';
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return null;
        }
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            return null;
        }

        rewind($handle);
        $contents = stream_get_contents($handle);
        if ($contents === false) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return null;
        }
        $lines = array_values(array_filter(explode("\n", $contents), static fn(string $line): bool => $line !== ''));
        $previousStatus = null;
        if ($lines) {
            $previous = json_decode($lines[count($lines) - 1], true);
            if (is_array($previous) && is_string($previous['status'] ?? null)) {
                $previousStatus = $previous['status'];
            }
        }
        $transition = $previousStatus === null ? 'initial observation'
            : ($previousStatus !== $result['status'] ? "{$previousStatus} -> {$result['status']}" : '');
        $entry = [
            'time' => date('c'),
            'status' => (string) $result['status'],
            'ms' => $durationMs,
            'message' => substr((string) $result['message'], 0, 180),
            'transition' => $transition,
        ];
        $line = json_encode($entry, JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return null;
        }

        $limit = max(20, min((int) ($config['learning_health_history_limit'] ?? 200), 1000));
        $lines[] = $line;
        $lines = array_slice($lines, -$limit);
        $retained = implode("\n", $lines) . "\n";
        if (strlen($retained) > 262144) {
            $lines = array_slice($lines, -max(20, (int) floor($limit / 2)));
            $retained = implode("\n", $lines) . "\n";
        }
        $saved = ftruncate($handle, 0)
            && rewind($handle)
            && fwrite($handle, $retained) === strlen($retained)
            && fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        return $saved ? ['transition' => $transition] : null;
    }

    private function probe(array $config): array
    {
        $url = trim((string) ($config['learning_health_url'] ?? ''));
        if ($url === '') {
            return [
                'status' => 'warn',
                'message' => 'Learning service health endpoint is not configured',
                'details' => ['The student-facing app URL alone cannot confirm that learning APIs, workers, or queues are healthy.'],
                'remediation' => 'Set learning_health_url to a small health endpoint that reports only component names and active/degraded/down states.',
            ];
        }

        $parts = parse_url($url);
        if (
            filter_var($url, FILTER_VALIDATE_URL) === false
            || !is_array($parts)
            || !in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            return [
                'status' => 'fail',
                'message' => 'Learning service health URL is invalid',
                'details' => ['Use an HTTP(S) URL without embedded credentials.'],
                'remediation' => 'Correct learning_health_url in config.php and keep the health route private or access-controlled.',
            ];
        }

        if (function_exists('curl_init')) {
            [$code, $body, $error] = $this->fetchWithCurl($url);
        } elseif (filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            [$code, $body, $error] = $this->fetchWithStreams($url);
        } else {
            return [
                'status' => 'warn',
                'message' => 'Learning service health probe cannot run',
                'details' => ['Enable cURL or allow_url_fopen to verify the configured health endpoint.'],
                'remediation' => 'Enable the cURL extension, or enable PHP URL streams if permitted by your runtime policy.',
            ];
        }

        if ($error !== '') {
            return [
                'status' => 'fail',
                'message' => 'Learning service health endpoint is unreachable',
                'details' => [$error],
                'remediation' => 'Check the learning API/worker status, route and proxy configuration, then review the application logs for the first exception.',
            ];
        }

        if ($code >= 500) {
            return [
                'status' => 'fail',
                'message' => "Learning service returned HTTP {$code}",
                'details' => ['The health endpoint responded with a server error.'],
                'remediation' => 'Inspect the learning service and worker logs around the scan time; verify database and queue dependencies before restarting.',
            ];
        }
        if ($code < 200 || $code >= 300) {
            return [
                'status' => 'warn',
                'message' => "Learning health endpoint returned HTTP {$code}",
                'details' => ['The health route may be misconfigured or access-restricted.'],
                'remediation' => 'Verify the configured route and its access policy from the Sentinel host.',
            ];
        }

        $payload = json_decode($body, true);
        if (!is_array($payload)) {
            return [
                'status' => 'ok',
                'message' => "Learning service is responding (HTTP {$code})",
                'details' => ['The endpoint returned success without a JSON component summary.'],
                'remediation' => null,
            ];
        }

        $state = strtolower((string) ($payload['status'] ?? ''));
        $status = match ($state) {
            'active', 'ok', 'healthy', 'up' => 'ok',
            'degraded', 'warning', 'partial' => 'warn',
            'down', 'failed', 'unhealthy', 'inactive', 'crashed' => 'fail',
            '' => 'warn',
            default => 'warn',
        };
        $details = ["Health endpoint: HTTP {$code}", 'Reported learning state: ' . ($state !== '' ? $state : 'unknown')];
        $components = $payload['components'] ?? $payload['services'] ?? [];

        if (is_array($components)) {
            foreach (array_slice($components, 0, 12, true) as $name => $component) {
                $componentName = preg_replace('/[^A-Za-z0-9_. -]/', '', (string) $name) ?: 'unnamed';
                $componentState = is_array($component)
                    ? (string) ($component['status'] ?? $component['state'] ?? 'unknown')
                    : (is_scalar($component) ? (string) $component : 'unknown');
                $componentState = strtolower(substr(preg_replace('/[^A-Za-z0-9_. -]/', '', $componentState) ?: 'unknown', 0, 40));
                $details[] = "Component {$componentName}: {$componentState}";
                if (in_array($componentState, ['down', 'failed', 'unhealthy', 'inactive', 'stopped', 'crashed'], true)) {
                    $status = 'fail';
                } elseif (in_array($componentState, ['degraded', 'warning', 'unknown'], true) && $status === 'ok') {
                    $status = 'warn';
                }
            }
        }

        $message = $status === 'ok'
            ? 'Learning service and reported components are active'
            : ($status === 'fail' ? 'Learning service or a reported component is down' : 'Learning service health is degraded or incomplete');
        $remediation = $status === 'ok' ? null
            : 'Use the component state and scan timestamp to inspect the matching service/worker logs and dependency health; do not expose stack traces on the public health route.';

        return [
            'status' => $status,
            'message' => $message,
            'details' => $details,
            'remediation' => $remediation,
        ];
    }

    /** @return array{int,string,string} */
    private function fetchWithCurl(string $url): array
    {
        $body = '';
        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 6,
            CURLOPT_USERAGENT => 'DevSentinel-Health/1.0',
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_BODY_BYTES) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $success = curl_exec($handle);
        $errorCode = curl_errno($handle);
        $code = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        return $success === false
            ? [0, '', "Health endpoint request failed (cURL error {$errorCode}); check the route, network path, and service logs."]
            : [$code, $body, ''];
    }

    /** @return array{int,string,string} */
    private function fetchWithStreams(string $url): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 6,
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 0,
                'header' => "Accept: application/json\r\nUser-Agent: DevSentinel-Health/1.0\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $body = @file_get_contents($url, false, $context, 0, self::MAX_BODY_BYTES + 1);
        $headers = $http_response_header ?? [];
        if ($body === false || !$headers) {
            return [0, '', 'Health endpoint request failed; check the route, network path, and service logs.'];
        }
        if (strlen($body) > self::MAX_BODY_BYTES) {
            return [0, '', 'Health endpoint response exceeded the 16 KB safety limit.'];
        }
        if (!preg_match('/\s(\d{3})\s/', (string) $headers[0], $match)) {
            return [0, '', 'Health endpoint returned an unreadable HTTP status line.'];
        }

        return [(int) $match[1], $body, ''];
    }
}
