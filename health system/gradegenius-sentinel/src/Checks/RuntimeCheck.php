<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class RuntimeCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Runtime & Dependencies';
    }

    public function category(): string
    {
        return 'runtime';
    }

    public function run(array $config): array
    {
        $status = 'ok';
        $details = [];
        $remediations = [];
        $root = realpath($config['app_root'] ?? '') ?: ($config['app_root'] ?? '');

        // 1. PHP Runtime checks
        $minPhp = $config['min_php'] ?? '8.1.0';
        if (version_compare(PHP_VERSION, $minPhp, '<')) {
            $status = 'fail';
            $details[] = "PHP " . PHP_VERSION . " is obsolete (minimum required: {$minPhp})";
            $remediations[] = "Upgrade PHP runtime to >= {$minPhp}";
        } else {
            $details[] = 'PHP Version: ' . PHP_VERSION;
        }

        // Sensitive PHP INI directives
        $iniChecks = [
            'display_errors'     => ['val' => false, 'sev' => 'fail', 'desc' => 'display_errors is enabled (leaks stack traces to end users)'],
            'expose_php'         => ['val' => false, 'sev' => 'warn', 'desc' => 'expose_php reveals PHP version in HTTP headers'],
            'allow_url_include'  => ['val' => false, 'sev' => 'fail', 'desc' => 'allow_url_include is enabled (Remote Code Inclusion vulnerability)'],
            'session.cookie_httponly' => ['val' => true, 'sev' => 'warn', 'desc' => 'session.cookie_httponly is Off (session tokens accessible to JS/XSS)'],
            'session.use_strict_mode' => ['val' => true, 'sev' => 'warn', 'desc' => 'session.use_strict_mode is Off'],
        ];

        foreach ($iniChecks as $directive => $expected) {
            $current = filter_var(ini_get($directive), FILTER_VALIDATE_BOOLEAN);
            if ($current !== $expected['val']) {
                $status = $this->worse($status, $expected['sev']);
                $details[] = $expected['desc'];
                if ($expected['sev'] === 'fail' && !in_array("Edit php.ini: set {$directive} = " . ($expected['val'] ? 'On' : 'Off'), $remediations, true)) {
                    $remediations[] = "Edit php.ini: set {$directive} = " . ($expected['val'] ? 'On' : 'Off');
                }
            }
        }

        // Required extensions
        $reqExts = $config['required_extensions'] ?? [];
        foreach ($reqExts as $ext) {
            if (!extension_loaded($ext)) {
                $status = 'fail';
                $details[] = "Missing PHP extension: {$ext}";
                $remediations[] = OsHelper::isLinux()
                    ? "Install extension: sudo apt install php-{$ext} (or yum/apk equivalent)"
                    : "Enable extension '{$ext}' in your php.ini";
            }
        }

        // 2. Composer Dependency Security Audit (if composer.lock exists)
        if ($root && is_file($root . '/composer.lock') && OsHelper::canExec()) {
            [$rc, $out] = OsHelper::exec("composer audit --locked --working-dir=" . escapeshellarg($root));
            if ($rc !== 0 && !empty($out)) {
                $status = $this->worse($status, 'warn');
                $details[] = 'Composer audit detected security advisories in dependencies';
                $remediations[] = 'Run "composer audit" and update vulnerable packages with "composer update <package>"';
            } else {
                $details[] = 'Composer: all locked packages pass security advisory audit';
            }
        }

        // 3. Node.js Ecosystem Detection & Audit (if package.json exists)
        if ($root && is_file($root . '/package.json')) {
            $pkg = json_decode((string) file_get_contents($root . '/package.json'), true);
            $pkgName = $pkg['name'] ?? 'Node project';
            $details[] = "Node ecosystem detected: {$pkgName}";

            if (is_file($root . '/package-lock.json') && OsHelper::canExec()) {
                [$rc, $out] = OsHelper::exec("cd " . escapeshellarg($root) . " && npm audit --json");
                if ($rc !== 0 && !empty($out)) {
                    $audit = json_decode($out, true);
                    $vulns = $audit['metadata']['vulnerabilities'] ?? null;
                    if ($vulns) {
                        $high = ($vulns['high'] ?? 0) + ($vulns['critical'] ?? 0);
                        if ($high > 0) {
                            $status = $this->worse($status, 'fail');
                            $details[] = "NPM Audit: {$high} high/critical vulnerabilities found in package-lock.json";
                            $remediations[] = 'Run "npm audit fix" or upgrade compromised dependencies in ' . $root;
                        } else {
                            $details[] = 'NPM dependencies checked: no critical vulnerabilities';
                        }
                    }
                }
            }
        }

        // 4. Python Ecosystem Detection
        if ($root && (is_file($root . '/requirements.txt') || is_file($root . '/pyproject.toml'))) {
            $details[] = 'Python ecosystem detected (requirements.txt / pyproject.toml)';
        }

        $message = $status === 'ok'
            ? 'Runtime environment & dependencies are healthy'
            : ($status === 'warn' ? 'Runtime configuration recommendations' : 'Critical runtime misconfiguration or vulnerable dependencies');

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
