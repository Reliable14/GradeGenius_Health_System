<?php
declare(strict_types=1);

namespace Sentinel;

require_once __DIR__ . '/Contracts/CheckInterface.php';
require_once __DIR__ . '/Platform/OsHelper.php';
require_once __DIR__ . '/AuthAudit.php';
require_once __DIR__ . '/Checks/SystemCheck.php';
require_once __DIR__ . '/Checks/RuntimeCheck.php';
require_once __DIR__ . '/Checks/DatabaseCheck.php';
require_once __DIR__ . '/Checks/SecurityCheck.php';
require_once __DIR__ . '/Checks/CodeScanCheck.php';
require_once __DIR__ . '/Checks/GitCheck.php';
require_once __DIR__ . '/Checks/ProcessCheck.php';
require_once __DIR__ . '/Checks/IntegrityCheck.php';
require_once __DIR__ . '/Checks/LogCheck.php';
require_once __DIR__ . '/Checks/CustomCheck.php';
require_once __DIR__ . '/Checks/LearningHealthCheck.php';
require_once __DIR__ . '/Checks/PortExposureCheck.php';
require_once __DIR__ . '/Checks/DashboardAuthCheck.php';
require_once __DIR__ . '/Checks/ProductionReadinessCheck.php';

use Sentinel\Contracts\CheckInterface;
use Sentinel\Checks\SystemCheck;
use Sentinel\Checks\RuntimeCheck;
use Sentinel\Checks\DatabaseCheck;
use Sentinel\Checks\SecurityCheck;
use Sentinel\Checks\CodeScanCheck;
use Sentinel\Checks\GitCheck;
use Sentinel\Checks\ProcessCheck;
use Sentinel\Checks\IntegrityCheck;
use Sentinel\Checks\LogCheck;
use Sentinel\Checks\CustomCheck;
use Sentinel\Checks\LearningHealthCheck;
use Sentinel\Checks\PortExposureCheck;
use Sentinel\Checks\DashboardAuthCheck;
use Sentinel\Checks\ProductionReadinessCheck;

/**
 * DevSentinel - Developer & IT Technician Health, Security, and Observability Engine.
 * Runs diagnostic checks across System, Runtime, Database, Security, DevOps, and Logs.
 */
final class Sentinel
{
    /** @var CheckInterface[] */
    private array $checks = [];

    public function __construct(private array $cfg)
    {
        @mkdir($this->cfg['data_dir'], 0750, true);
        $this->registerDefaultChecks();
    }

    /**
     * Register core diagnostic checks.
     */
    private function registerDefaultChecks(): void
    {
        $this->checks = [
            new SystemCheck(),
            new RuntimeCheck(),
            new DatabaseCheck(),
            new SecurityCheck(),
            new CodeScanCheck(),
            new GitCheck(),
            new ProcessCheck(),
            new IntegrityCheck(),
            new LogCheck(),
            new CustomCheck(),
            new LearningHealthCheck(),
            new PortExposureCheck(),
            new DashboardAuthCheck(),
            new ProductionReadinessCheck(),
        ];
    }

    /**
     * Add a custom check implementing CheckInterface.
     */
    public function addCheck(CheckInterface $check): void
    {
        $this->checks[] = $check;
    }

    /**
     * Run all configured diagnostic checks.
     */
    public function runAll(): array
    {
        $results = [];

        foreach ($this->checks as $check) {
            $t = microtime(true);
            try {
                $r = $check->run($this->cfg);
            } catch (\Throwable $e) {
                $r = [
                    'status'      => 'fail',
                    'message'     => 'Check crashed: ' . $e->getMessage(),
                    'details'     => ['Exception: ' . get_class($e), $e->getFile() . ':' . $e->getLine()],
                    'remediation' => 'Inspect PHP error log and check definition',
                ];
            }

            $r['name']        = $check->name();
            $r['category']    = $check->category();
            $r['remediation'] = $r['remediation'] ?? null;
            $r['ms']          = (int) round((microtime(true) - $t) * 1000);
            $results[] = $r;
        }

        $overall = 'ok';
        foreach ($results as $r) {
            if ($r['status'] === 'fail') {
                $overall = 'fail';
                break;
            }
            if ($r['status'] === 'warn') {
                $overall = 'warn';
            }
        }

        $report = [
            'app'     => $this->cfg['app_name'] ?? 'DevSentinel',
            'time'    => date('c'),
            'host'    => gethostname() ?: 'unknown',
            'os'      => PHP_OS . ' (' . php_uname('m') . ')',
            'overall' => $overall,
            'checks'  => $results,
        ];

        $this->save($report);
        $this->maybeAlert($report);

        return $report;
    }

    public function lastReport(): ?array
    {
        $f = $this->cfg['data_dir'] . '/last_report.json';
        return is_file($f) ? json_decode((string) file_get_contents($f), true) : null;
    }

    public function history(int $limit = 48): array
    {
        $f = $this->cfg['data_dir'] . '/history.jsonl';
        if (!is_file($f)) return [];
        $lines = array_slice(file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [], -$limit);
        return array_values(array_filter(array_map(fn($l) => json_decode($l, true), $lines)));
    }

    public function createBaseline(): int
    {
        $integrityCheck = new IntegrityCheck();
        $hashes = $integrityCheck->hashTree($this->cfg);
        file_put_contents($this->cfg['data_dir'] . '/baseline.json', json_encode($hashes, JSON_PRETTY_PRINT), LOCK_EX);
        return count($hashes);
    }

    /* ------------------------------------------------------------ alerts */

    private function maybeAlert(array $report): void
    {
        $stateFile = $this->cfg['data_dir'] . '/state.json';
        $state = is_file($stateFile) ? (json_decode((string) file_get_contents($stateFile), true) ?: []) : [];

        $prev   = $state['overall'] ?? 'ok';
        $lastAt = $state['alerted_at'] ?? 0;
        $cool   = ($this->cfg['alerts']['cooldown_minutes'] ?? 60) * 60;

        $bad = $report['overall'] !== 'ok';
        $changed = $prev !== $report['overall'];
        $recovered = !$bad && $prev !== 'ok';

        if (($bad && ($changed || time() - $lastAt > $cool)) || $recovered) {
            $this->sendAlert($report, $recovered);
            $state['alerted_at'] = time();
        }
        $state['overall'] = $report['overall'];
        file_put_contents($stateFile, json_encode($state), LOCK_EX);
    }

    private function sendAlert(array $report, bool $recovered): void
    {
        $a = $this->cfg['alerts'] ?? [];
        $title = $recovered
            ? "[{$report['app']}] RECOVERED: All diagnostic checks passing"
            : "[{$report['app']}] " . strtoupper($report['overall']) . ': Technician Attention Needed';

        $body = $title . "\nHost: {$report['host']} | OS: {$report['os']}\nTime: {$report['time']}\n\n";

        foreach ($report['checks'] as $c) {
            if ($c['status'] === 'ok') continue;
            $body .= sprintf("[%s] [%s] %s: %s\n", strtoupper($c['status']), strtoupper($c['category']), $c['name'], $c['message']);
            foreach (array_slice($c['details'], 0, 4) as $line) {
                $body .= "    • {$line}\n";
            }
            if (!empty($c['remediation'])) {
                $body .= "    💡 Fix: {$c['remediation']}\n";
            }
            $body .= "\n";
        }

        if (!empty($a['dashboard_url'])) {
            $body .= "Dashboard: {$a['dashboard_url']}\n";
        }

        if (!empty($a['email'])) {
            $headers = 'From: ' . ($a['from'] ?? 'sentinel@localhost') . "\r\nContent-Type: text/plain; charset=utf-8";
            foreach ($a['email'] as $to) {
                @mail($to, $title, $body, $headers);
            }
        }

        if (!empty($a['webhook']) && function_exists('curl_init')) {
            $ch = curl_init($a['webhook']);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                CURLOPT_POSTFIELDS     => json_encode(['text' => $body]),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 8,
            ]);
            curl_exec($ch);
            curl_close($ch);
        }
    }

    private function save(array $report): void
    {
        $dir = $this->cfg['data_dir'];
        file_put_contents("{$dir}/last_report.json", json_encode($report, JSON_PRETTY_PRINT), LOCK_EX);

        $summary = [
            'time'    => $report['time'],
            'overall' => $report['overall'],
            'counts'  => array_count_values(array_column($report['checks'], 'status')),
        ];
        file_put_contents("{$dir}/history.jsonl", json_encode($summary) . "\n", FILE_APPEND | LOCK_EX);

        $f = "{$dir}/history.jsonl";
        if (filesize($f) > 512 * 1024) {
            $keep = array_slice(file($f), -500);
            file_put_contents($f, implode('', $keep), LOCK_EX);
        }
    }
}
