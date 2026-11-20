<?php
declare(strict_types=1);

namespace Sentinel\Platform;

/**
 * Cross-platform hardware, OS, and process abstraction layer.
 * Works uniformly across Linux, macOS, and Windows with caching to ensure high performance.
 */
final class OsHelper
{
    private static ?array $cachedMetrics = null;
    private static float $cacheTimestamp = 0.0;

    public static function isWindows(): bool
    {
        return DIRECTORY_SEPARATOR === '\\';
    }

    public static function isMac(): bool
    {
        return PHP_OS_FAMILY === 'Darwin';
    }

    public static function isLinux(): bool
    {
        return PHP_OS_FAMILY === 'Linux';
    }

    public static function canExec(): bool
    {
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
        return function_exists('exec') && !in_array('exec', $disabled, true);
    }

    /**
     * Executes a command safely and returns [exitCode, stdoutString].
     */
    public static function exec(string $command): array
    {
        if (!self::canExec()) {
            return [-1, ''];
        }
        $out = [];
        $rc = 0;
        exec($command . ' 2>&1', $out, $rc);
        return [$rc, implode("\n", $out)];
    }

    /**
     * Fetch combined hardware metrics (Memory + CPU). Cached for 15s to keep probes ultra-fast.
     */
    private static function fetchSystemMetrics(): void
    {
        $now = microtime(true);
        if (self::$cachedMetrics !== null && ($now - self::$cacheTimestamp) < 15.0) {
            return;
        }

        $metrics = [
            'memory' => null,
            'cpu'    => ['cores' => 1],
        ];

        // 1. Linux
        if (self::isLinux()) {
            if (is_readable('/proc/meminfo')) {
                $m = (string) file_get_contents('/proc/meminfo');
                if (preg_match('/MemTotal:\s+(\d+)\s+kB/', $m, $a) && preg_match('/MemAvailable:\s+(\d+)\s+kB/', $m, $b)) {
                    $totalKb = (float) $a[1];
                    $availKb = (float) $b[1];
                    $usedKb  = $totalKb - $availKb;
                    $metrics['memory'] = [
                        'total_mb' => round($totalKb / 1024, 1),
                        'free_mb'  => round($availKb / 1024, 1),
                        'used_pct' => round(($usedKb / $totalKb) * 100, 1),
                    ];
                }
            }
            if (is_readable('/proc/cpuinfo')) {
                $metrics['cpu']['cores'] = max(1, preg_match_all('/^processor\s*:/m', (string) file_get_contents('/proc/cpuinfo')));
            }
            if (function_exists('sys_getloadavg') && ($load = sys_getloadavg())) {
                $metrics['cpu']['load1']    = (float) $load[0];
                $metrics['cpu']['load5']    = (float) $load[1];
                $metrics['cpu']['load15']   = (float) $load[2];
                $metrics['cpu']['per_core'] = round($load[0] / $metrics['cpu']['cores'], 2);
            }
        }
        // 2. Windows: Single combined PowerShell command to minimize execution overhead
        elseif (self::isWindows() && self::canExec()) {
            $cores = isset($_SERVER['NUMBER_OF_PROCESSORS']) ? max(1, (int) $_SERVER['NUMBER_OF_PROCESSORS']) : 1;
            $metrics['cpu']['cores'] = $cores;

            $psCmd = 'powershell -NoProfile -Command "'
                . '$os = Get-CimInstance Win32_OperatingSystem;'
                . '$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average;'
                . '[PSCustomObject]@{TotalMem=$os.TotalVisibleMemorySize; FreeMem=$os.FreePhysicalMemory; CpuLoad=$cpu} | ConvertTo-Json"';

            [$rc, $out] = self::exec($psCmd);
            if ($rc === 0 && !empty($out)) {
                $data = json_decode($out, true);
                if (isset($data['TotalMem'], $data['FreeMem'])) {
                    $totalKb = (float) $data['TotalMem'];
                    $freeKb  = (float) $data['FreeMem'];
                    $usedKb  = $totalKb - $freeKb;
                    $metrics['memory'] = [
                        'total_mb' => round($totalKb / 1024, 1),
                        'free_mb'  => round($freeKb / 1024, 1),
                        'used_pct' => round(($usedKb / $totalKb) * 100, 1),
                    ];
                }
                if (isset($data['CpuLoad']) && is_numeric($data['CpuLoad'])) {
                    $metrics['cpu']['load_pct'] = (float) $data['CpuLoad'];
                    $metrics['cpu']['per_core'] = round(((float) $data['CpuLoad']) / 100, 2);
                }
            }
        }
        // 3. macOS
        elseif (self::isMac() && self::canExec()) {
            [$rc, $out] = self::exec('sysctl -n hw.ncpu hw.memsize');
            if ($rc === 0) {
                $lines = explode("\n", trim($out));
                if (isset($lines[0]) && is_numeric($lines[0])) {
                    $metrics['cpu']['cores'] = (int) $lines[0];
                }
                if (isset($lines[1]) && is_numeric($lines[1])) {
                    $metrics['memory'] = [
                        'total_mb' => round((float) $lines[1] / (1024 * 1024), 1),
                        'free_mb'  => 0.0,
                        'used_pct' => 0.0,
                    ];
                }
            }
            if (function_exists('sys_getloadavg') && ($load = sys_getloadavg())) {
                $metrics['cpu']['load1']    = (float) $load[0];
                $metrics['cpu']['load5']    = (float) $load[1];
                $metrics['cpu']['load15']   = (float) $load[2];
                $metrics['cpu']['per_core'] = round($load[0] / $metrics['cpu']['cores'], 2);
            }
        }

        self::$cachedMetrics = $metrics;
        self::$cacheTimestamp = $now;
    }

    public static function getMemoryMetrics(): ?array
    {
        self::fetchSystemMetrics();
        return self::$cachedMetrics['memory'] ?? null;
    }

    public static function getCpuMetrics(): array
    {
        self::fetchSystemMetrics();
        return self::$cachedMetrics['cpu'] ?? ['cores' => 1];
    }

    public static function getDiskMetrics(string $path): ?array
    {
        $target = realpath($path) ?: $path;
        $total = @disk_total_space($target);
        $free  = @disk_free_space($target);

        if ($total === false || $free === false || $total <= 0) {
            $total = @disk_total_space(__DIR__);
            $free  = @disk_free_space(__DIR__);
        }

        if ($total !== false && $free !== false && $total > 0) {
            $used = $total - $free;
            return [
                'total_gb' => round($total / (1024 ** 3), 1),
                'free_gb'  => round($free / (1024 ** 3), 1),
                'used_gb'  => round($used / (1024 ** 3), 1),
                'used_pct' => round(($used / $total) * 100, 1),
            ];
        }

        return null;
    }

    public static function formatBytes(int|float $bytes, int $decimals = 1): string
    {
        $sz = ['B', 'KB', 'MB', 'GB', 'TB'];
        $factor = (int) floor((strlen((string)(int)$bytes) - 1) / 3);
        return sprintf("%.{$decimals}f %s", $bytes / (1024 ** $factor), $sz[$factor] ?? 'B');
    }
}
