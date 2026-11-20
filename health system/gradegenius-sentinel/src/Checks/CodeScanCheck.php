<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class CodeScanCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Code & Secret Security';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        $root = realpath($config['app_root'] ?? '');
        if (!$root || !is_dir($root)) {
            return [
                'status'      => 'warn',
                'message'     => 'app_root path not accessible for code scanning',
                'details'     => ['Configured path: ' . ($config['app_root'] ?? 'empty')],
                'remediation' => 'Verify app_root in config.php points to your application source folder',
            ];
        }

        $status = 'ok';
        $details = [];
        $remediations = [];

        // 1. Syntax Linting (PHP)
        $phpCli = $config['php_cli'] ?? 'php';
        $canExec = OsHelper::canExec();
        $lintErrors = [];
        $filesChecked = 0;
        $maxFiles = (int) ($config['max_files'] ?? 1500);

        if ($canExec) {
            foreach ($this->scanFiles($root, ['php', 'phtml'], $config) as $file) {
                if (++$filesChecked > $maxFiles) break;
                [$rc, $out] = OsHelper::exec("{$phpCli} -l " . escapeshellarg($file));
                if ($rc !== 0) {
                    $cleanOut = trim(implode(' ', array_filter(explode("\n", $out), fn($l) => !str_starts_with($l, 'Errors parsing'))));
                    $lintErrors[] = $this->rel($file, $root) . ': ' . $cleanOut;
                    if (count($lintErrors) >= 15) break;
                }
            }

            if ($lintErrors) {
                $status = 'fail';
                $details[] = count($lintErrors) . ' file(s) failed PHP syntax linting';
                foreach ($lintErrors as $e) $details[] = "SYNTAX ERROR: {$e}";
                $remediations[] = 'Fix PHP parse errors before deployment to prevent HTTP 500 crashes';
            } else {
                $details[] = "Syntax Lint: {$filesChecked} PHP files verified syntax OK";
            }
        }

        // 2. Suspicious Patterns & Leaked Secrets Scanner
        $rules = [
            '/\beval\s*\(/i'                                                        => ['Dangerous eval() call', 'high'],
            '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{80,}/'                      => ['Obfuscated Base64 payload', 'high'],
            '/\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)/i' => ['Command execution injection from request param', 'high'],
            '/\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)/i'   => ['Dynamic file inclusion from user input', 'high'],
            '/\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i'                  => ['Insecure unserialize() on untrusted user input', 'high'],
            '/(SELECT|INSERT|UPDATE|DELETE)[^;"\']{0,80}["\']\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)/i' => ['Direct SQL concatenation with user input (SQLi risk)', 'high'],
            '/->query\s*\(\s*["\'][^"\']*\$\w+/i'                                   => ['Variable interpolated into SQL query string', 'medium'],
            '/\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i'                      => ['extract() on user request array', 'high'],
            '/\becho\s+\$_(GET|POST|REQUEST|COOKIE)\b/i'                            => ['Unescaped request variable echoed directly (XSS)', 'medium'],
            // Secret scanners:
            '/-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/'             => ['Unencrypted Private Key checked into repository', 'high'],
            '/\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/'                           => ['GitHub Personal Access Token leaked', 'high'],
            '/\bAKIA[0-9A-Z]{16}\b/'                                                => ['AWS Access Key ID hardcoded in source', 'high'],
            '/\b(AIza[0-9A-Za-z\\-_]{35})\b/'                                       => ['Google Cloud API Key hardcoded in source', 'high'],
            '/\b(password|secret|api_key|apikey|token)\s*=\s*[\'"][^\'"]{10,}[\'"]\s*;/i' => ['Probable hardcoded credential or token', 'medium'],
        ];

        $codeFindings = [];
        $highSeverityCount = 0;
        $scannedCount = 0;
        $ignoreFiles = $config['scan_ignore_files'] ?? [];

        foreach ($this->scanFiles($root, ['php', 'phtml', 'js', 'ts', 'py', 'env'], $config) as $file) {
            if (++$scannedCount > $maxFiles) break;
            $rel = $this->rel($file, $root);
            if (in_array($rel, $ignoreFiles, true) || str_contains($file, 'sentinel')) continue;

            $lines = @file($file, FILE_IGNORE_NEW_LINES) ?: [];
            foreach ($lines as $lineNum => $line) {
                if (strlen($line) > 3000) $line = substr($line, 0, 3000);
                foreach ($rules as $pattern => [$title, $severity]) {
                    if (preg_match($pattern, $line)) {
                        $codeFindings[] = strtoupper($severity) . " {$rel}:" . ($lineNum + 1) . " - {$title}";
                        if ($severity === 'high') $highSeverityCount++;
                    }
                }
            }
            if (count($codeFindings) >= 30) break;
        }

        if ($codeFindings) {
            $status = $highSeverityCount > 0 ? 'fail' : $this->worse($status, 'warn');
            $details[] = count($codeFindings) . " security pattern(s) identified ({$highSeverityCount} high severity)";
            foreach (array_slice($codeFindings, 0, 15) as $f) $details[] = $f;
            $remediations[] = 'Move hardcoded credentials to environment variables (.env) and sanitize dynamic inputs with prepared statements / parameterized queries';
        } else {
            $details[] = "Code Security: {$scannedCount} files scanned, no critical patterns or leaked secrets detected";
        }

        $message = $status === 'ok'
            ? 'Source code syntax valid and secrets secured'
            : ($status === 'warn' ? 'Code review advisories detected' : 'Critical code vulnerabilities or leaked secrets found');

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

    private function rel(string $path, string $root): string
    {
        $normalizedRoot = str_replace('\\', '/', rtrim($root, '\\/'));
        $normalizedPath = str_replace('\\', '/', $path);
        return ltrim(substr($normalizedPath, strlen($normalizedRoot)), '/');
    }

    private function scanFiles(string $root, array $extensions, array $config): \Generator
    {
        $skip = array_merge(['vendor', 'node_modules', '.git', 'storage', 'cache', 'uploads'], $config['scan_exclude_dirs'] ?? []);
        $dirs = new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS);
        $filter = new \RecursiveCallbackFilterIterator($dirs, function (\SplFileInfo $f, $k, $it) use ($skip) {
            return $it->hasChildren() ? !in_array($f->getFilename(), $skip, true) : true;
        });

        foreach (new \RecursiveIteratorIterator($filter) as $f) {
            /** @var \SplFileInfo $f */
            if ($f->isFile() && !$f->isLink() && in_array(strtolower($f->getExtension()), $extensions, true)) {
                yield $f->getPathname();
            }
        }
    }
}
