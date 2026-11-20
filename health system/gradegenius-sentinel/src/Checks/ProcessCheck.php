<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class ProcessCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Services & Containers';
    }

    public function category(): string
    {
        return 'devops';
    }

    public function run(array $config): array
    {
        if (!OsHelper::canExec()) {
            return [
                'status'      => 'ok',
                'message'     => 'Service monitoring skipped (exec disabled)',
                'details'     => [],
                'remediation' => null,
            ];
        }

        $status = 'ok';
        $details = [];
        $remediations = [];

        // 1. Docker Daemon & Container Inspection
        [$rcDocker, $dockerOut] = OsHelper::exec('docker ps -a --format "{{.Names}}\t{{.Status}}\t{{.State}}"');
        if ($rcDocker === 0 && !empty(trim($dockerOut))) {
            $containers = array_filter(explode("\n", trim($dockerOut)));
            $runningCount = 0;
            $unhealthyCount = 0;

            foreach ($containers as $cLine) {
                $parts = explode("\t", trim($cLine));
                $cName = $parts[0] ?? 'container';
                $cStatus = $parts[1] ?? 'unknown';
                $cState = $parts[2] ?? 'unknown';

                if (str_starts_with($cState, 'running')) {
                    $runningCount++;
                } else {
                    $unhealthyCount++;
                    $details[] = "Container '{$cName}' state: {$cStatus}";
                }
            }

            if ($unhealthyCount > 0) {
                $status = $this->worse($status, 'warn');
                $details[] = "Docker: {$unhealthyCount} non-running or unhealthy container(s) detected";
                $remediations[] = 'Check Docker logs: run "docker logs <container_name>" or "docker-compose up -d"';
            } else {
                $details[] = "Docker: {$runningCount} active container(s) running normally";
            }
        }

        // 2. PM2 Node Process Manager Check (if node environment)
        [$rcPm2, $pm2Out] = OsHelper::exec('pm2 jlist');
        if ($rcPm2 === 0 && !empty(trim($pm2Out))) {
            $pm2Data = json_decode($pm2Out, true);
            if (is_array($pm2Data) && !empty($pm2Data)) {
                $stopped = 0;
                foreach ($pm2Data as $proc) {
                    $pName = $proc['name'] ?? 'app';
                    $pStatus = $proc['pm2_env']['status'] ?? 'unknown';
                    $restarts = $proc['pm2_env']['restart_time'] ?? 0;

                    if ($pStatus !== 'online') {
                        $stopped++;
                        $details[] = "PM2: App '{$pName}' is {$pStatus} (Restarts: {$restarts})";
                    }
                }
                if ($stopped > 0) {
                    $status = $this->worse($status, 'fail');
                    $remediations[] = 'Restart failed PM2 workers: run "pm2 restart all" or "pm2 logs"';
                } else {
                    $details[] = 'PM2: All ' . count($pm2Data) . ' application(s) online';
                }
            }
        }

        // 3. Monitored System Services (e.g. ['nginx', 'redis-server', 'supervisor'])
        $monitoredServices = $config['monitored_services'] ?? [];
        if (!empty($monitoredServices) && OsHelper::isLinux()) {
            foreach ($monitoredServices as $svc) {
                [$rcSvc, $outSvc] = OsHelper::exec("systemctl is-active " . escapeshellarg($svc));
                $state = trim($outSvc);
                if ($state !== 'active') {
                    $status = 'fail';
                    $details[] = "Service '{$svc}' is {$state}";
                    $remediations[] = "Start service: sudo systemctl start {$svc}";
                } else {
                    $details[] = "Service '{$svc}' is active";
                }
            }
        }

        if (empty($details)) {
            $details[] = 'No specific Docker, PM2, or systemd services configured for probing';
        }

        $message = $status === 'ok'
            ? 'Monitored services and containers are running smoothly'
            : ($status === 'warn' ? 'Service or container warning detected' : 'Service outage or stopped container detected');

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
