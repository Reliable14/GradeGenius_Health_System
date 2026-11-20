<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class GitCheck implements CheckInterface
{
    public function name(): string
    {
        return 'Git & Version Control';
    }

    public function category(): string
    {
        return 'devops';
    }

    public function run(array $config): array
    {
        $root = realpath($config['app_root'] ?? '');
        if (!$root || !is_dir($root . '/.git')) {
            return [
                'status'      => 'ok',
                'message'     => 'Not a Git repository (or .git omitted in production)',
                'details'     => ['Git repository metadata not found in ' . ($root ?: 'app_root')],
                'remediation' => null,
            ];
        }

        if (!OsHelper::canExec()) {
            return [
                'status'      => 'warn',
                'message'     => 'exec() disabled; cannot query Git CLI',
                'details'     => ['.git directory is present.'],
                'remediation' => null,
            ];
        }

        $status = 'ok';
        $details = [];
        $remediations = [];

        // 1. Current Branch & Commit Info
        [$rcBranch, $branchOut] = OsHelper::exec("git -C " . escapeshellarg($root) . " rev-parse --abbrev-ref HEAD");
        $branch = trim($branchOut);

        [$rcLog, $logOut] = OsHelper::exec("git -C " . escapeshellarg($root) . " log -1 --format=\"%h - %s (%cr by %an)\"");
        $lastCommit = trim($logOut);

        if ($rcBranch === 0) {
            $details[] = "Branch: {$branch}";
            if ($rcLog === 0 && !empty($lastCommit)) {
                $details[] = "Latest commit: {$lastCommit}";
            }
        }

        // 2. Check for Dirty Working Directory (uncommitted files/edits on server)
        [$rcStatus, $statusOut] = OsHelper::exec("git -C " . escapeshellarg($root) . " status --porcelain");
        $dirtyLines = array_filter(explode("\n", trim($statusOut)));

        if (!empty($dirtyLines)) {
            $status = 'warn';
            $details[] = count($dirtyLines) . ' uncommitted change(s) or untracked file(s) in working tree';
            foreach (array_slice($dirtyLines, 0, 5) as $line) {
                $details[] = '  ' . trim($line);
            }
            if (count($dirtyLines) > 5) {
                $details[] = '  ...and ' . (count($dirtyLines) - 5) . ' more files';
            }
            $remediations[] = 'Server has uncommitted changes: inspect with "git status" or revert unintended hotfixes';
        } else {
            $details[] = 'Working tree is clean (no untracked or modified files)';
        }

        $message = $status === 'ok'
            ? "Git repository is clean on branch '{$branch}'"
            : "Git repository has uncommitted modifications on branch '{$branch}'";

        return [
            'status'      => $status,
            'message'     => $message,
            'details'     => $details,
            'remediation' => $remediations ? implode(' | ', $remediations) : null,
        ];
    }
}
