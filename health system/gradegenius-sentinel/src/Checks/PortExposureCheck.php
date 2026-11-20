<?php
declare(strict_types=1);

namespace Sentinel\Checks;

use Sentinel\Contracts\CheckInterface;
use Sentinel\Platform\OsHelper;

final class PortExposureCheck implements CheckInterface
{
    private const HIGH_RISK_PORTS = [
        21 => 'FTP',
        23 => 'Telnet',
        139 => 'NetBIOS Session Service',
        445 => 'SMB',
        1433 => 'Microsoft SQL Server',
        2375 => 'Unauthenticated Docker API',
        3306 => 'MySQL',
        33060 => 'MySQL X Protocol',
        3389 => 'Remote Desktop',
        5432 => 'PostgreSQL',
        5900 => 'VNC',
        6379 => 'Redis',
        9200 => 'Elasticsearch',
        11211 => 'Memcached',
        27017 => 'MongoDB',
        9229 => 'Node.js Inspector',
    ];

    public function name(): string
    {
        return 'Listening Ports & Exposure';
    }

    public function category(): string
    {
        return 'security';
    }

    public function run(array $config): array
    {
        if (!OsHelper::canExec()) {
            return [
                'status' => 'warn',
                'message' => 'Local listening-port inventory is unavailable',
                'details' => ['exec is disabled, so Sentinel cannot inspect local TCP listeners. No remote hosts are scanned.'],
                'remediation' => 'Enable the required local system-command permission or review listeners with the host operating system tools.',
            ];
        }

        $command = OsHelper::isWindows() ? 'netstat -ano -p tcp'
            : (OsHelper::isLinux() ? 'ss -lnt' : 'netstat -an');
        [$exitCode, $output] = OsHelper::exec($command);
        if ($exitCode !== 0 || trim($output) === '') {
            if (!OsHelper::isWindows() && $command !== 'netstat -an') {
                [$exitCode, $output] = OsHelper::exec('netstat -an');
            }
        }
        if ($exitCode !== 0 || trim($output) === '') {
            return [
                'status' => 'warn',
                'message' => 'Could not enumerate local TCP listeners',
                'details' => ['The operating system did not return a listener inventory. This check is local-only.'],
                'remediation' => OsHelper::isWindows()
                    ? 'Run "netstat -ano -p tcp" locally and verify each listening address and owning process.'
                    : 'Install or allow "ss" or "netstat", then verify local listeners and firewall rules.',
            ];
        }

        $listeners = $this->parseListeners($output);
        if (!$listeners) {
            return [
                'status' => 'warn',
                'message' => 'Listener output was available but could not be parsed',
                'details' => ['No remote scan was performed; verify listeners with the operating system network tools.'],
                'remediation' => 'Review the local "netstat" or "ss" output and confirm the Sentinel user can inspect it.',
            ];
        }

        $configuredRiskPorts = $config['audit_internal_ports'] ?? [];
        $riskPorts = self::HIGH_RISK_PORTS;
        foreach ($configuredRiskPorts as $port => $service) {
            if (is_numeric($port) && (int) $port > 0 && (int) $port <= 65535) {
                $riskPorts[(int) $port] = (string) $service;
            }
        }
        $publicPorts = array_map('intval', $config['public_tcp_ports'] ?? [80, 443]);
        $processNames = $this->processNames($listeners);
        $firewall = $this->firewallStatus();
        $status = 'ok';
        $riskDetails = [];
        $otherDetails = [];
        $remediations = [];
        $highRiskAllInterfaces = 0;
        $highRiskOnPrivateInterface = 0;
        $needsGeneralReview = false;

        foreach ($listeners as $listener) {
            $port = $listener['port'];
            $service = $riskPorts[$port] ?? 'TCP service';
            $binding = $listener['binding'];
            $pid = $listener['pid'] !== null ? '; PID ' . $listener['pid'] : '';
            $process = $listener['pid'] !== null && isset($processNames[$listener['pid']])
                ? '; process ' . $processNames[$listener['pid']]
                : '';
            $detail = "{$listener['address']} ({$service}; {$binding}{$pid}{$process})";

            if (isset($riskPorts[$port]) && $binding === 'all interfaces') {
                $status = 'fail';
                $highRiskAllInterfaces++;
                $riskDetails[] = "HIGH RISK listener: {$detail}";
                $remediations[] = "{$service} on port {$port}: bind to loopback or a trusted private interface, require authentication, and restrict inbound firewall rules.";
            } elseif (isset($riskPorts[$port]) && $binding === 'specific interface') {
                if ($status === 'ok') $status = 'warn';
                $highRiskOnPrivateInterface++;
                $riskDetails[] = "Review sensitive listener: {$detail}";
                $remediations[] = "{$service} on port {$port}: confirm the bound interface is private, require authentication, and restrict the allowed source range.";
            } elseif ($binding !== 'loopback only' && !in_array($port, $publicPorts, true)) {
                if ($status === 'ok') $status = 'warn';
                $otherDetails[] = "Verify intended exposure: {$detail}";
                $needsGeneralReview = true;
            } else {
                $otherDetails[] = "Local listener: {$detail}";
            }
        }

        if ($needsGeneralReview) {
            $remediations[] = 'Identify listener PIDs locally (Windows: "Get-Process -Id <PID>"; Linux: "ss -lntp"), then restrict non-required binds and inbound firewall source ranges.';
        }
        if ($firewall['state'] === 'disabled') {
            if ($status === 'ok') {
                $status = 'warn';
            }
            $riskDetails[] = 'Host firewall appears disabled; confirm this with the operating-system firewall console.';
            $remediations[] = 'Review the host firewall policy with the system administrator before enabling or changing rules.';
        }
        $details = [
            count($listeners) . ' TCP listener(s) found on this host.',
            'Local TCP listeners only; no external hosts or networks were scanned.',
            'Listeners are not necessarily internet-accessible; actual exposure also depends on routing, NAT, and firewall rules.',
            $firewall['summary'],
        ];
        $details = array_merge($details, array_slice($riskDetails, 0, 20), array_slice($otherDetails, 0, 10));
        if (count($riskDetails) > 20 || count($otherDetails) > 10) {
            $details[] = 'Additional listeners omitted from this summary; review the local operating-system inventory.';
        }

        $message = $status === 'fail'
            ? "{$highRiskAllInterfaces} sensitive service listener(s) bound to all interfaces"
            : ($status === 'warn'
                ? ($highRiskOnPrivateInterface
                    ? "{$highRiskOnPrivateInterface} sensitive service listener(s) need interface/firewall review"
                    : 'Review non-loopback listeners and firewall exposure')
                : count($listeners) . ' local TCP listener(s) inventoried; no sensitive service bound beyond loopback');

        return [
            'status' => $status,
            'message' => $message,
            'details' => $details,
            'remediation' => $remediations ? implode(' | ', array_unique($remediations)) : null,
        ];
    }

    /** @param array<int, array{address:string,port:int,binding:string,pid:?int}> $listeners
     *  @return array<int,string>
     */
    private function processNames(array $listeners): array
    {
        if (!OsHelper::canExec()) {
            return [];
        }
        $wanted = [];
        foreach ($listeners as $listener) {
            if ($listener['pid'] !== null && $listener['binding'] !== 'loopback only') {
                $wanted[$listener['pid']] = true;
            }
            if (count($wanted) >= 20) {
                break;
            }
        }
        if (!$wanted) {
            return [];
        }

        [$exitCode, $output] = OsHelper::isWindows()
            ? OsHelper::exec('tasklist /FO CSV /NH')
            : OsHelper::exec('ps -eo pid=,comm=');
        if ($exitCode !== 0 || trim($output) === '') {
            return [];
        }

        $names = [];
        foreach (explode("\n", $output) as $line) {
            if (OsHelper::isWindows()) {
                $columns = str_getcsv(trim($line), ',', '"', '\\');
                if (count($columns) < 2 || !ctype_digit($columns[1])) {
                    continue;
                }
                $pid = (int) $columns[1];
                $name = $columns[0];
            } elseif (preg_match('/^\s*(\d+)\s+(.+?)\s*$/', $line, $match)) {
                $pid = (int) $match[1];
                $name = $match[2];
            } else {
                continue;
            }
            if (isset($wanted[$pid])) {
                $names[$pid] = substr(preg_replace('/[^A-Za-z0-9_. -]/', '', $name) ?: 'unknown', 0, 100);
            }
        }
        return $names;
    }

    /** @return array{state:string,summary:string} */
    private function firewallStatus(): array
    {
        if (!OsHelper::canExec()) {
            return ['state' => 'unknown', 'summary' => 'Host firewall state could not be checked (system command execution is unavailable).'];
        }

        if (OsHelper::isWindows()) {
            [$code, $output] = OsHelper::exec('netsh advfirewall show allprofiles state');
            preg_match_all('/^\s*State\s+(ON|OFF)\s*$/mi', $output, $matches);
            $states = array_map('strtoupper', $matches[1] ?? []);
            if ($code === 0 && $states) {
                $disabled = in_array('OFF', $states, true);
                return [
                    'state' => $disabled ? 'disabled' : 'enabled',
                    'summary' => $disabled
                        ? 'Windows Defender Firewall is disabled for at least one reported profile.'
                        : 'Windows Defender Firewall is enabled for all reported profiles.',
                ];
            }
        } elseif (OsHelper::isLinux()) {
            [$code, $output] = OsHelper::exec('ufw status');
            if ($code === 0 && preg_match('/^Status:\s*(active|inactive)\s*$/mi', $output, $match)) {
                $disabled = strtolower($match[1]) === 'inactive';
                return [
                    'state' => $disabled ? 'disabled' : 'enabled',
                    'summary' => 'UFW is ' . strtolower($match[1]) . '.',
                ];
            }
            [$code, $output] = OsHelper::exec('firewall-cmd --state');
            if ($code === 0 && trim($output) !== '') {
                return ['state' => 'enabled', 'summary' => 'firewalld reports: ' . substr(trim($output), 0, 120) . '.'];
            }
        } elseif (OsHelper::isMac()) {
            [$code, $output] = OsHelper::exec('pfctl -s info');
            if ($code === 0 && preg_match('/Status:\s*(Enabled|Disabled)/i', $output, $match)) {
                $disabled = strtolower($match[1]) === 'disabled';
                return [
                    'state' => $disabled ? 'disabled' : 'enabled',
                    'summary' => 'macOS packet filter is ' . strtolower($match[1]) . '.',
                ];
            }
        }

        return ['state' => 'unknown', 'summary' => 'Host firewall state could not be determined with available local tools.'];
    }

    /** @return array<int, array{address:string,port:int,binding:string,pid:?int}> */
    private function parseListeners(string $output): array
    {
        $listeners = [];
        foreach (explode("\n", $output) as $line) {
            $local = '';
            $pid = null;
            if (preg_match('/^\s*TCP\s+(\S+)\s+\S+\s+LISTENING(?:\s+(\d+))?/i', $line, $match)) {
                $local = $match[1];
                $pid = isset($match[2]) ? (int) $match[2] : null;
            } elseif (preg_match('/^\s*LISTEN\s+\d+\s+\d+\s+(\S+)/i', $line, $match)) {
                $local = $match[1];
            } elseif (preg_match('/^\s*tcp[46]?\s+(?:\d+\s+){2}(\S+)\s+\S+\s+LISTEN\b/i', $line, $match)) {
                $local = $match[1];
            } else {
                continue;
            }

            if (!preg_match('/(?:[:.])(\d+)$/', $local, $portMatch)) {
                continue;
            }
            $port = (int) $portMatch[1];
            if ($port < 1 || $port > 65535) {
                continue;
            }

            $address = substr($local, 0, -strlen($portMatch[0]));
            $normalized = strtolower(trim($address, '[]'));
            if (
                $normalized === '127.0.0.1'
                || $normalized === '::1'
                || str_starts_with($normalized, '127.')
                || $normalized === 'localhost'
            ) {
                $binding = 'loopback only';
            } elseif ($normalized === '0.0.0.0' || $normalized === '::' || $normalized === '*' || $normalized === '') {
                $binding = 'all interfaces';
            } else {
                $binding = 'specific interface';
            }

            $listeners[$local] = [
                'address' => $local,
                'port' => $port,
                'binding' => $binding,
                'pid' => $pid,
            ];
        }

        return array_values($listeners);
    }
}
