<?php
declare(strict_types=1);

namespace Sentinel\Contracts;

/**
 * Interface that every diagnostic check must implement.
 */
interface CheckInterface
{
    /**
     * Unique display name of the check (e.g. "System Resources", "Git Repository").
     */
    public function name(): string;

    /**
     * Category for grouping in reports and dashboard:
     * 'system' | 'runtime' | 'database' | 'security' | 'devops' | 'logs'
     */
    public function category(): string;

    /**
     * Run the check.
     *
     * Expected return structure:
     * [
     *   'status'      => 'ok' | 'warn' | 'fail',
     *   'message'     => 'Human readable summary',
     *   'details'     => ['bullet 1', 'bullet 2'],
     *   'remediation' => 'Optional command or advice to resolve issues'
     * ]
     *
     * @param array $config The full Sentinel configuration
     * @return array
     */
    public function run(array $config): array;
}
