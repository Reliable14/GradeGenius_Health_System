<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;

final class IntegrityCheck implements CheckInterface
{
    public function name(): string
    {
        return 'File Integrity & Tampering';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        $dataDir = $config['data_dir'] ?? (__DIR__ . '/../../data');
        $baselineFile = $dataDir . '/baseline.json';

        $current = $this->hashTree($config);

        if (!is_file($baselineFile)) {
            return [
                'status'      => 'warn',
                'message'     => 'No trusted baseline established yet',
                'details'     => ['File tampering detection is inactive until a baseline snapshot is created.'],
                'remediation' => 'Run "php cli.php baseline" to snapshot the clean repository state',
            ];
        }

        $base = json_decode((string) file_get_contents($baselineFile), true) ?: [];

        $new = array_diff_key($current, $base);
        $gone = array_diff_key($base, $current);
        $changed = [];
        foreach ($current as $path => $hash) {
            if (isset($base[$path]) && $base[$path] !== $hash) {
                $changed[] = $path;
            }
        }

        $details = [];
        foreach ($changed as $p) $details[] = "MODIFIED: {$p}";
        foreach (array_keys($new) as $p)  $details[] = "NEW: {$p}";
        foreach (array_keys($gone) as $p) $details[] = "DELETED: {$p}";

        if (empty($details)) {
            return [
                'status'      => 'ok',
                'message'     => count($current) . ' tracked file(s) strictly match trusted baseline',
                'details'     => ['All codebase hashes verified intact.'],
                'remediation' => null,
            ];
        }

        $status = ($new || $changed) ? 'fail' : 'warn';
        $message = count($details) . ' file change(s) detected compared to baseline';

        return [
            'status'      => $status,
            'message'     => $message,
            'details'     => array_slice($details, 0, 40),
            'remediation' => 'If this was a planned deploy, update baseline: "php cli.php baseline". Otherwise, inspect modified files immediately for unauthorized changes.',
        ];
    }

    public function hashTree(array $config): array
    {
        $root = realpath($config['app_root'] ?? '');
        if (!$root || !is_dir($root)) return [];

        $extensions = $config['integrity_extensions'] ?? ['php', 'phtml', 'js', 'ts', 'py', 'htaccess', 'ini', 'json'];
        $skip = array_merge(['vendor', 'node_modules', '.git', 'storage', 'cache', 'uploads', 'data'], $config['scan_exclude_dirs'] ?? []);

        $dirs = new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS);
        $filter = new \RecursiveCallbackFilterIterator($dirs, function (\SplFileInfo $f, $k, $it) use ($skip) {
            return $it->hasChildren() ? !in_array($f->getFilename(), $skip, true) : true;
        });

        $hashes = [];
        $normalizedRoot = str_replace('\\', '/', rtrim($root, '\\/'));

        foreach (new \RecursiveIteratorIterator($filter) as $f) {
            /** @var \SplFileInfo $f */
            if ($f->isFile() && !$f->isLink() && in_array(strtolower($f->getExtension()), $extensions, true)) {
                $fullPath = $f->getPathname();
                if (str_contains($fullPath, 'sentinel')) continue;
                $rel = ltrim(substr(str_replace('\\', '/', $fullPath), strlen($normalizedRoot)), '/');
                $hashes[$rel] = hash_file('sha256', $fullPath);
            }
        }

        ksort($hashes);
        return $hashes;
    }
}
