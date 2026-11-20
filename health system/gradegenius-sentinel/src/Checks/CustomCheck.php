<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class CustomCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Custom Technician Probes';
    }

    public function category(): string
    {
        return 'devops';
    }

    public function run(array $config): array
    {
        $customDir = $config['custom_checks_dir'] ?? (dirname(__DIR__, 2) . '/checks.d');
        if (!is_dir($customDir) || !OsHelper::canExec()) {
            return [
                'status'      => 'ok',
                'message'     => 'No custom technician probes defined',
                'details'     => ['Drop custom scripts into checks.d/ to add custom infrastructure probes.'],
                'remediation' => null,
            ];
        }

        $files = glob($customDir . '/*');
        if (empty($files)) {
            return [
                'status'      => 'ok',
                'message'     => 'No custom technician probes in checks.d/',
                'details'     => ['Drop executable scripts into checks.d/ to extend DevSentinel.'],
                'remediation' => null,
            ];
        }

        $status = 'ok';
        $details = [];
        $remediations = [];
        $probeCount = 0;

        foreach ($files as $file) {
            if (!is_file($file)) continue;
            $probeName = basename($file);
            $probeCount++;

            $cmd = escapeshellarg($file);
            if (str_ends_with($file, '.php')) {
                $cmd = ($config['php_cli'] ?? 'php') . ' ' . $cmd;
            } elseif (str_ends_with($file, '.ps1') && OsHelper::isWindows()) {
                $cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' . $cmd;
            }

            [$rc, $out] = OsHelper::exec($cmd);
            $outTrimmed = trim($out);

            if ($rc === 0) {
                $details[] = "[OK] {$probeName}: " . ($outTrimmed ?: 'probe passed');
            } elseif ($rc === 1) {
                $status = $this->worse($status, 'warn');
                $details[] = "[WARN] {$probeName}: " . ($outTrimmed ?: 'probe warning');
            } else {
                $status = 'fail';
                $details[] = "[FAIL] {$probeName}: " . ($outTrimmed ?: 'probe failed (exit code ' . $rc . ')');
                $remediations[] = "Review custom probe '{$probeName}' output and failure condition";
            }
        }

        $message = $status === 'ok'
            ? "All {$probeCount} custom technician probe(s) passed"
            : "Issues reported by custom technician probes in checks.d/";

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
