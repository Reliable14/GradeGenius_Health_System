<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/src/Sentinel.php';
$configFile = getenv('SENTINEL_CONFIG') ?: __DIR__ . '/config.php';
$cfg = require $configFile;
$s = new Sentinel\Sentinel($cfg);

$cmd = $argv[1] ?? 'doctor';

// ANSI terminal helpers
$c = [
    'reset'   => "\033[0m",
    'bold'    => "\033[1m",
    'dim'     => "\033[2m",
    'red'     => "\033[31m",
    'green'   => "\033[32m",
    'yellow'  => "\033[33m",
    'blue'    => "\033[34m",
    'magenta' => "\033[35m",
    'cyan'    => "\033[36m",
    'white'   => "\033[37m",
    'bg_red'  => "\033[41m",
    'bg_green'=> "\033[42m",
    'bg_warn' => "\033[43m",
];

switch ($cmd) {
    case 'doctor':
    case 'run':
        $verbose = in_array('-v', $argv, true) || $cmd === 'doctor';
        $r = $s->runAll();

        $overallBadge = match ($r['overall']) {
            'ok'   => "{$c['bg_green']}{$c['bold']}  HEALTHY  {$c['reset']}",
            'warn' => "{$c['bg_warn']}{$c['bold']}  WARNING  {$c['reset']}",
            default=> "{$c['bg_red']}{$c['bold']}  FAILING  {$c['reset']}",
        };

        echo "\n{$c['bold']}{$c['cyan']}DevSentinel Diagnostic Workbench{$c['reset']}\n";
        echo "{$c['dim']}Target: {$r['app']} | Host: {$r['host']} | OS: {$r['os']} | Time: {$r['time']}{$c['reset']}\n";
        echo "Status: {$overallBadge}\n\n";

        // Group checks by category
        $byCat = [];
        foreach ($r['checks'] as $check) {
            $cat = $check['category'] ?? 'general';
            $byCat[$cat][] = $check;
        }

        $categoryIcons = [
            'system'   => '🖥️  SYSTEM HARDWARE & OS',
            'runtime'  => '🚀 RUNTIME & DEPENDENCIES',
            'database' => '🗄️  DATABASES & CACHES',
            'security' => '🛡️  SECURITY, SECRETS & SSL',
            'devops'   => '📦 DEVOPS, GIT & SERVICES',
            'logs'     => '📜 LOGS & EXCEPTION METRICS',
        ];

        foreach ($byCat as $catKey => $checks) {
            $header = $categoryIcons[$catKey] ?? strtoupper($catKey);
            echo "{$c['bold']}{$c['blue']}{$header}{$c['reset']}\n";

            foreach ($checks as $chk) {
                $statusTag = match ($chk['status']) {
                    'ok'   => "{$c['green']}[ OK ]{$c['reset']}",
                    'warn' => "{$c['yellow']}[WARN]{$c['reset']}",
                    default=> "{$c['red']}{$c['bold']}[FAIL]{$c['reset']}",
                };

                printf("  %s %-26s %s {$c['dim']}(%d ms){$c['reset']}\n", $statusTag, $chk['name'], $chk['message'], $chk['ms']);

                if (($verbose || $chk['status'] !== 'ok') && !empty($chk['details'])) {
                    foreach ($chk['details'] as $detail) {
                        echo "         {$c['dim']}•{$c['reset']} {$detail}\n";
                    }
                }

                if (!empty($chk['remediation'])) {
                    echo "         {$c['yellow']}💡 Quick Fix:{$c['reset']} {$c['bold']}{$chk['remediation']}{$c['reset']}\n";
                }
            }
            echo "\n";
        }

        // Summary footer
        $counts = array_count_values(array_column($r['checks'], 'status'));
        echo "{$c['bold']}Summary:{$c['reset']} " . ($counts['ok'] ?? 0) . " passed, " . ($counts['warn'] ?? 0) . " warnings, " . ($counts['fail'] ?? 0) . " failures.\n";

        $exitCode = match ($r['overall']) {
            'fail'  => 2,
            'warn'  => 1,
            default => 0,
        };
        exit($exitCode);

    case 'audit':
        echo "{$c['bold']}{$c['cyan']}Running DevSentinel Security & Vulnerability Audit...{$c['reset']}\n";
        $r = $s->runAll();
        $secChecks = array_filter($r['checks'], fn($chk) => in_array($chk['category'], ['security', 'runtime'], true));
        foreach ($secChecks as $chk) {
            $tag = match ($chk['status']) {
                'ok'   => "{$c['green']}[ PASS ]{$c['reset']}",
                'warn' => "{$c['yellow']}[ ADVISORY ]{$c['reset']}",
                default=> "{$c['red']}{$c['bold']}[ VULNERABILITY ]{$c['reset']}",
            };
            echo "{$tag} {$c['bold']}{$chk['name']}{$c['reset']}: {$chk['message']}\n";
            foreach ($chk['details'] as $d) echo "    - {$d}\n";
            if (!empty($chk['remediation'])) echo "    {$c['yellow']}Fix: {$chk['remediation']}{$c['reset']}\n";
            echo "\n";
        }
        break;

    case 'json':
        $r = $s->runAll();
        echo json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        exit($r['overall'] === 'fail' ? 2 : 0);

    case 'baseline':
        $n = $s->createBaseline();
        echo "{$c['green']}Baseline snapshot recorded for {$n} files.{$c['reset']}\n";
        echo "Any new, modified, or deleted files will now be tracked by File Integrity.\n";
        break;

    case 'make-password':
        echo 'Choose a dashboard password: ';
        $pw = trim((string) fgets(STDIN));
        if (strlen($pw) < 12) {
            fwrite(STDERR, "Use at least 12 characters.\n");
            exit(1);
        }
        echo "\nGenerated password hash for config.php or SENTINEL_PASSWORD_HASH:\n";
        echo password_hash($pw, PASSWORD_DEFAULT) . "\n";
        break;

    default:
        echo "DevSentinel CLI - Technician Diagnostics\n";
        echo "Usage: php cli.php [doctor | run [-v] | audit | json | baseline | make-password]\n";
}
