<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class SystemCheck implements CheckInterface
{
    public function name(): string
    {
        return 'System Resources';
    }

    public function category(): string
    {
        return 'system';
    }

    public function run(array $config): array
    {
        $t = $config['thresholds'] ?? [];
        $diskWarn = $t['disk_warn'] ?? 80;
        $diskFail = $t['disk_fail'] ?? 90;
        $memWarn  = $t['mem_warn'] ?? 85;
        $memFail  = $t['mem_fail'] ?? 95;
        $loadWarn = $t['load_warn'] ?? 1.0;
        $loadFail = $t['load_fail'] ?? 2.0;

        $status = 'ok';
        $details = [];
        $remediations = [];

        // 1. Disk
        $disk = OsHelper::getDiskMetrics($config['app_root'] ?? __DIR__);
        if ($disk) {
            $details[] = sprintf('Disk: %s%% used (%s GB free of %s GB)', $disk['used_pct'], $disk['free_gb'], $disk['total_gb']);
            if ($disk['used_pct'] >= $diskFail) {
                $status = 'fail';
                $details[] = 'CRITICAL: Disk storage is almost exhausted!';
                $remediations[] = 'Free disk space: run "journalctl --vacuum-time=3d" or "docker system prune -af --volumes", or check large files with "du -sh /* | sort -h"';
            } elseif ($disk['used_pct'] >= $diskWarn) {
                $status = $this->worse($status, 'warn');
                $details[] = 'WARNING: High disk utilization';
                $remediations[] = 'Plan disk cleanup or log rotation before partition reaches capacity';
            }
        }

        // 2. Memory
        $mem = OsHelper::getMemoryMetrics();
        if ($mem) {
            $details[] = sprintf('RAM: %s%% used (%s MB free of %s MB)', $mem['used_pct'], $mem['free_mb'], $mem['total_mb']);
            if ($mem['used_pct'] >= $memFail) {
                $status = 'fail';
                $details[] = 'CRITICAL: Memory exhaustion detected (OOM risk)';
                $remediations[] = 'Check top consuming processes: "ps aux --sort=-%mem | head -n 10" or "Get-Process | Sort-Object WorkingSet64 -Descending"';
            } elseif ($mem['used_pct'] >= $memWarn) {
                $status = $this->worse($status, 'warn');
                $details[] = 'WARNING: High RAM utilization';
            }
        }

        // 3. CPU / Load
        $cpu = OsHelper::getCpuMetrics();
        if (isset($cpu['load1'])) {
            $details[] = sprintf('CPU Load: %.2f / %.2f / %.2f (%d cores, %.2f/core)', $cpu['load1'], $cpu['load5'], $cpu['load15'], $cpu['cores'], $cpu['per_core']);
            if ($cpu['per_core'] >= $loadFail) {
                $status = 'fail';
                $remediations[] = 'High CPU load: investigate runaway processes using "top -b -n 1 | head -n 20" or "htop"';
            } elseif ($cpu['per_core'] >= $loadWarn) {
                $status = $this->worse($status, 'warn');
            }
        } elseif (isset($cpu['load_pct'])) {
            $details[] = sprintf('CPU Usage: %.1f%% across %d core(s)', $cpu['load_pct'], $cpu['cores']);
            if ($cpu['load_pct'] >= 90) {
                $status = 'fail';
                $remediations[] = 'High CPU utilization: inspect task manager or "Get-Process | Sort-Object CPU -Descending"';
            } elseif ($cpu['load_pct'] >= 75) {
                $status = $this->worse($status, 'warn');
            }
        } else {
            $details[] = sprintf('CPU: %d detected core(s)', $cpu['cores']);
        }

        $message = $status === 'ok'
            ? 'All system metrics (Disk, RAM, CPU) within healthy limits'
            : ($status === 'warn' ? 'Hardware resource pressure detected' : 'Critical hardware resource constraint');

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
}
