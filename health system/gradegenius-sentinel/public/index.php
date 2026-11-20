<?php
declare(strict_types=1);

require __DIR__ . '/../src/Sentinel.php';
require_once __DIR__ . '/../src/AuthAudit.php';
$configFile = getenv('SENTINEL_CONFIG') ?: __DIR__ . '/../config.php';
$cfg = require $configFile;
$sentinel = new Sentinel\Sentinel($cfg);

/* ---------- security hardening headers ---------- */
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Cache-Control: no-store');

$allowed = $cfg['dashboard_allowed_ips'] ?? [];
if ($allowed && !in_array($_SERVER['REMOTE_ADDR'] ?? '', $allowed, true)) {
    http_response_code(403);
    exit('Forbidden');
}

/* ---------- token API for external monitors / Prometheus: X-Sentinel-Token header or ?token= ---------- */
$token = $cfg['api_token'] ?? '';
$sentHeader = $_SERVER['HTTP_X_SENTINEL_TOKEN'] ?? '';
$sentQuery  = $_GET['token'] ?? '';
$sent = $sentHeader !== '' ? $sentHeader : $sentQuery;

if ($token !== '' && $sent !== '' && hash_equals($token, $sent)) {
    header('Content-Type: application/json');
    $report = isset($_GET['run']) ? $sentinel->runAll() : $sentinel->lastReport();
    if (!$report) $report = $sentinel->runAll();
    http_response_code(($report['overall'] ?? 'fail') === 'fail' ? 503 : 200);
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- session management ---------- */
session_set_cookie_params([
    'httponly' => true,
    'secure'   => !empty($_SERVER['HTTPS']),
    'samesite' => 'Strict',
]);
session_name('devsentinel');
session_start();
$_SESSION['csrf'] ??= bin2hex(random_bytes(16));
$csrf = $_SESSION['csrf'];
$e = fn($v) => htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf = $_POST['csrf'] ?? '';
    if (!is_string($postedCsrf) || !hash_equals($csrf, $postedCsrf)) {
        http_response_code(400);
        exit('Invalid CSRF token');
    }
    $action = $_POST['action'] ?? '';

    if ($action === 'login') {
        $hash = $cfg['dashboard_password_hash'] ?? '';
        $locked = ($_SESSION['lock_until'] ?? 0) > time();
        if ($locked) {
            Sentinel\AuthAudit::record($cfg, 'rate_limited', $_SERVER);
            $error = 'Rate limited. Please wait 60 seconds before trying again.';
        } elseif ($hash !== '' && password_verify((string) ($_POST['password'] ?? ''), $hash)) {
            Sentinel\AuthAudit::record($cfg, 'login_success', $_SERVER);
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $_SESSION['fails'] = 0;
        } else {
            Sentinel\AuthAudit::record($cfg, 'login_failed', $_SERVER);
            $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
            if ($_SESSION['fails'] >= 5) {
                $_SESSION['lock_until'] = time() + 60;
                $_SESSION['fails'] = 0;
                Sentinel\AuthAudit::record($cfg, 'lockout', $_SERVER);
            }
            usleep(300000);
            $error = $hash === '' ? 'No password set. Run: php cli.php make-password' : 'Wrong password.';
        }
    } elseif (!empty($_SESSION['auth'])) {
        if ($action === 'scan') {
            $sentinel->runAll();
        } elseif ($action === 'logout') {
            session_destroy();
        } elseif ($action === 'demo_scenario' && !empty($cfg['demo_scenarios_enabled'])) {
            $scenario = $_POST['scenario'] ?? '';
            if (!is_string($scenario)) {
                http_response_code(400);
                exit('Unknown demo scenario');
            }
            if (!in_array($scenario, ['learning_down', 'login_burst', 'risky_listeners'], true)) {
                http_response_code(400);
                exit('Unknown demo scenario');
            }
            $_SESSION['demo_scenario'] = $scenario;
        } elseif ($action === 'clear_demo_scenario') {
            unset($_SESSION['demo_scenario']);
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}

$authed = !empty($_SESSION['auth']);
$authEventTypes = ['login_failed', 'login_success', 'rate_limited', 'lockout'];
$authEventCandidate = $_GET['auth_event'] ?? 'all';
$authEventFilter = is_string($authEventCandidate) ? $authEventCandidate : 'all';
if ($authEventFilter !== 'all' && !in_array($authEventFilter, $authEventTypes, true)) {
    $authEventFilter = 'all';
}
$authWindowCandidate = $_GET['auth_minutes'] ?? 60;
$authWindowMinutes = is_numeric($authWindowCandidate) ? max(1, min((int) $authWindowCandidate, 10080)) : 60;
$authEvents = $authed ? Sentinel\AuthAudit::recent($cfg, 1000) : [];

if ($authed && isset($_GET['auth_export'])) {
    if ($authEvents === null) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        exit('Authentication audit events could not be read.');
    }
    $cutoff = time() - ($authWindowMinutes * 60);
    $exportEvents = array_values(array_filter($authEvents, static function (array $event) use ($authEventFilter, $cutoff): bool {
        $time = strtotime($event['time']);
        return $time !== false
            && $time >= $cutoff
            && ($authEventFilter === 'all' || $event['event'] === $authEventFilter);
    }));
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="sentinel-auth-events.csv"');
    $stream = fopen('php://output', 'wb');
    fputcsv($stream, ['time', 'event', 'ip', 'user_agent'], ',', '"', '\\');
    foreach ($exportEvents as $event) {
        $row = [$event['time'], $event['event'], $event['ip'], $event['user_agent']];
        foreach ($row as &$cell) {
            if (preg_match('/^\s*[=+\-@]/', $cell)) {
                $cell = "'" . $cell;
            }
        }
        unset($cell);
        fputcsv($stream, $row, ',', '"', '\\');
    }
    fclose($stream);
    exit;
}

if ($authed && isset($_GET['json'])) {
    header('Content-Type: application/json');
    echo json_encode($sentinel->lastReport(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$report  = $authed ? $sentinel->lastReport() : null;
$history = $authed ? $sentinel->history(48) : [];
$learningHistory = $authed ? Sentinel\Checks\LearningHealthCheck::history($cfg, 20) : [];
$learningHistory = is_array($learningHistory) ? array_reverse($learningHistory) : [];
$authEvents = is_array($authEvents) ? array_reverse(array_values(array_filter(
    $authEvents,
    static function (array $event) use ($authEventFilter, $authWindowMinutes): bool {
        $time = strtotime($event['time']);
        return $time !== false
            && $time >= time() - ($authWindowMinutes * 60)
            && ($authEventFilter === 'all' || $event['event'] === $authEventFilter);
    }
))) : null;
$authEvents = is_array($authEvents) ? array_slice($authEvents, 0, 20) : null;
$demoScenarios = [
    'learning_down' => [
        'title' => 'Learning service outage',
        'status' => 'fail',
        'message' => 'Learning API is unreachable; course workers report stopped.',
        'details' => ['This is simulated only. No service is stopped and no health endpoint is changed.'],
        'next' => ['Check the learning API and worker process state.', 'Compare the outage start time with application and dependency logs.', 'Verify database and queue availability before attempting recovery.'],
    ],
    'login_burst' => [
        'title' => 'Repeated dashboard login failures',
        'status' => 'warn',
        'message' => 'Example burst: 8 failed attempts from 203.0.113.42 within 10 minutes.',
        'details' => ['203.0.113.0/24 is a documentation-only example address range.', 'No authentication events are written by this simulation.'],
        'next' => ['Correlate the source with trusted proxy and web-server logs.', 'Check rate limits and MFA policy.', 'Do not block an address until you rule out a shared or trusted source.'],
    ],
    'risky_listeners' => [
        'title' => 'Sensitive listeners need review',
        'status' => 'fail',
        'message' => 'Example: SMB and a database listener are bound beyond loopback.',
        'details' => ['This preview opens no ports and does not change firewall rules.', 'A non-loopback bind does not prove that a service is reachable from the internet.'],
        'next' => ['Identify the local process and confirm the service owner.', 'Check host firewall, router/NAT, and cloud ingress rules.', 'Restrict exposure only after confirming the service requirements.'],
    ],
];
$activeDemoScenario = !empty($cfg['demo_scenarios_enabled'])
    ? ($demoScenarios[$_SESSION['demo_scenario'] ?? ''] ?? null)
    : null;

$labels = ['ok' => 'Healthy', 'warn' => 'Warning', 'fail' => 'Failing'];
$statusCounts = ['ok' => 0, 'warn' => 0, 'fail' => 0];
$problems = 0;
$incidentFindings = [];
$incidentGroups = [];
$incidentSummaryText = '';

if ($report) {
    foreach ($report['checks'] as $index => $check) {
        $st = $check['status'] ?? 'fail';
        if (isset($statusCounts[$st])) $statusCounts[$st]++;
        if ($st !== 'ok') {
            $problems++;
            $finding = [
                'index' => $index,
                'category' => (string) ($check['category'] ?? 'general'),
                'name' => (string) ($check['name'] ?? 'Diagnostic check'),
                'status' => (string) $st,
                'message' => (string) ($check['message'] ?? 'Requires review'),
                'remediation' => (string) ($check['remediation'] ?? ''),
            ];
            $incidentFindings[] = $finding;
            $incidentGroups[$finding['category']][] = $finding;
        }
    }
    usort($incidentFindings, static fn(array $a, array $b): int => ($a['status'] === 'fail' ? 0 : 1) <=> ($b['status'] === 'fail' ? 0 : 1));
    if ($incidentFindings) {
        $incidentSummaryText = sprintf(
            "%d finding(s): %d critical, %d warning(s).",
            count($incidentFindings),
            count(array_filter($incidentFindings, static fn(array $finding): bool => $finding['status'] === 'fail')),
            count(array_filter($incidentFindings, static fn(array $finding): bool => $finding['status'] === 'warn'))
        );
        foreach ($incidentFindings as $finding) {
            $incidentSummaryText .= "\n[" . strtoupper($finding['status']) . "] {$finding['category']} / {$finding['name']}: {$finding['message']}";
            if ($finding['remediation'] !== '') {
                $incidentSummaryText .= "\nNext step: {$finding['remediation']}";
            }
        }
    }
}
$totalChecks = array_sum($statusCounts);
$headline = !$report ? 'No diagnostic scan on record'
    : ($report['overall'] === 'ok' ? 'All diagnostic checks are healthy'
    : ($problems === 1 ? '1 check requires technician attention' : "{$problems} checks require technician attention"));
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= $e($cfg['app_name'] ?? 'DevSentinel') ?> - Technician Workbench</title>
<style>
:root{
  color-scheme:light;
  --bg:#f4f6fb; --surface:#fff; --ink:#17223b; --muted:#6c7693; --line:#e2e6f0;
  --accent:#4f46e5; --accent-light:#eef2ff; --shadow:0 10px 30px rgba(23,34,59,.06);
  --ok:#16a34a; --warn:#d97706; --fail:#dc2626;
  --ok-bg:#dcfce7; --warn-bg:#fef3c7; --fail-bg:#fee2e2;
  --ok-card:#f0fdf4; --warn-card:#fffbeb; --fail-card:#fef2f2;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SFMono-Regular",Menlo,Monaco,Consolas,"Liberation Mono",monospace;
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#0c101c; --surface:#151b2e; --ink:#edf2f7; --muted:#94a3b8; --line:#25304a;
  --accent:#818cf8; --accent-light:#1e1b4b; --shadow:0 10px 30px rgba(0,0,0,.35);
  --ok:#4ade80; --warn:#fbbf24; --fail:#f87171;
  --ok-bg:#14532d; --warn-bg:#78350f; --fail-bg:#7f1d1d;
  --ok-card:#0f291e; --warn-card:#2d2109; --fail-card:#321414;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans)}
a{color:inherit;text-decoration:none}
button{font:inherit;cursor:pointer}
button:focus-visible,a:focus-visible,summary:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.app-shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}
.sidebar{display:flex;flex-direction:column;padding:26px 18px;border-right:1px solid var(--line);background:var(--surface)}
.brand{display:flex;align-items:center;gap:11px;margin:0 0 32px 6px;font-size:18px;font-weight:800;letter-spacing:-.03em}
.brand-mark{display:grid;width:36px;height:36px;place-items:center;border-radius:10px;background:var(--accent);color:#fff;font-size:18px}
.brand small{display:block;color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.03em}
.nav-label{margin:18px 10px 8px;color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
.sidebar nav{display:grid;gap:4px}
.sidebar nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:var(--muted);font-size:14px;font-weight:600}
.sidebar nav a.active,.sidebar nav a:hover{background:var(--accent-light);color:var(--accent)}
.side-card{margin-top:auto;padding:14px;border:1px solid var(--line);border-radius:12px;background:var(--bg)}
.side-card strong{display:block;font-size:13px}
.side-card small{display:block;margin-top:4px;color:var(--muted);font-size:12px}
.pulse{display:inline-block;width:8px;height:8px;margin-right:7px;border-radius:50%;background:var(--ok)}
.workspace{width:min(1400px,100%);margin:0 auto;padding:26px clamp(16px,3vw,40px) 56px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}
.eyebrow{display:block;color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
.topbar h1{margin:2px 0 0;font-size:22px;letter-spacing:-.03em}
.actions{display:flex;align-items:center;gap:8px}
.actions button,.theme-toggle{padding:8px 14px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);font-size:13px;font-weight:600}
.actions .primary{border-color:var(--accent);background:var(--accent);color:#fff}
.actions button:hover,.theme-toggle:hover{border-color:var(--accent)}
.hero{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:20px;padding:22px 26px;border:1px solid var(--line);border-left:6px solid var(--line);border-radius:14px;background:var(--surface);box-shadow:var(--shadow)}
.hero.ok{border-left-color:var(--ok);background:linear-gradient(115deg,var(--ok-card),var(--surface) 65%)}
.hero.warn{border-left-color:var(--warn);background:linear-gradient(115deg,var(--warn-card),var(--surface) 65%)}
.hero.fail{border-left-color:var(--fail);background:linear-gradient(115deg,var(--fail-card),var(--surface) 65%)}
.hero h3{margin:4px 0;font-size:clamp(19px,3vw,26px);letter-spacing:-.03em}
.hero p{margin:0;color:var(--muted);font-size:13px}
.hero-badges{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}
.badge{padding:3px 8px;border-radius:6px;background:var(--line);font:11px var(--mono);color:var(--ink)}
.hero-mark{display:grid;flex:none;width:52px;height:52px;place-items:center;border-radius:14px;background:var(--surface);color:var(--accent);font-size:24px;font-weight:800}

.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 24px}
.stat{padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:var(--surface);box-shadow:var(--shadow)}
.stat-label{color:var(--muted);font-size:12px;font-weight:700}
.stat-value{display:block;margin:4px 0 0;font-size:26px;font-weight:800;letter-spacing:-.04em}
.stat-value.ok{color:var(--ok)}.stat-value.warn{color:var(--warn)}.stat-value.fail{color:var(--fail)}
.stat-note{color:var(--muted);font-size:12px}

.category-tabs{display:flex;gap:6px;margin:0 0 16px;overflow-x:auto;padding-bottom:4px}
.tab-btn{padding:7px 14px;border:1px solid var(--line);border-radius:20px;background:var(--surface);color:var(--muted);font-size:13px;font-weight:600;white-space:nowrap}
.tab-btn.active,.tab-btn:hover{background:var(--accent);border-color:var(--accent);color:#fff}

.panel{padding:18px;border:1px solid var(--line);border-radius:14px;background:var(--surface);box-shadow:var(--shadow);margin-bottom:24px}
.panel h2{margin:0 0 8px;font-size:16px}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
.panel-note{margin:0;color:var(--muted);font-size:12px}
.finding-groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:12px 0}
.finding-group{padding:12px;border:1px solid var(--line);border-radius:9px;background:var(--bg)}
.finding-group strong{display:block;margin-bottom:6px;font-size:12px;text-transform:capitalize}
.finding-group a{display:block;margin-top:6px;color:var(--accent);font-size:13px;font-weight:600}
.summary-copy{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}
.summary-copy textarea{width:100%;min-height:84px;padding:9px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:12px/1.5 var(--mono);resize:vertical}
.inline-form{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:12px 0}
.inline-form select,.inline-form input,.inline-form button,.scenario-form button{padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--ink);font:inherit;font-size:12px}
.inline-form button,.scenario-form button{font-weight:700}
.inline-form button:hover,.scenario-form button:hover{border-color:var(--accent)}
.audit-table{width:100%;border-collapse:collapse;font-size:12px}
.audit-table th,.audit-table td{padding:8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}
.audit-table th{color:var(--muted);font-size:11px;text-transform:uppercase}
.audit-table-wrap{overflow-x:auto}
.scenario-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px;margin:12px 0}
.scenario-form{display:inline}
.scenario-form button{width:100%;min-height:44px}
.scenario-preview{padding:14px;border:1px dashed var(--warn);border-radius:10px;background:var(--warn-card)}
.scenario-preview h3{margin:0 0 6px;font-size:15px}
.scenario-preview ul{margin:8px 0 0;padding-left:20px;font-size:13px}
.state-tag{display:inline-block;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:800;text-transform:uppercase}
.state-tag.ok{background:var(--ok-bg);color:var(--ok)}.state-tag.warn{background:var(--warn-bg);color:var(--warn)}.state-tag.fail{background:var(--fail-bg);color:var(--fail)}
.strip{display:flex;gap:3px;align-items:flex-end;height:30px;margin:12px 0 6px}
.strip i{flex:1;min-width:3px;height:100%;border-radius:2px}
.strip i.ok{height:55%;background:var(--ok)}.strip i.warn{height:80%;background:var(--warn)}.strip i.fail{background:var(--fail)}
.cap{margin:0;color:var(--muted);font-size:12px}

.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;padding:0;margin:0;list-style:none}
details.check{height:100%;border:1px solid var(--line);border-left:5px solid var(--line);border-radius:12px;background:var(--surface);box-shadow:var(--shadow)}
details.check.ok{border-left-color:var(--ok);background:var(--ok-card)}
details.check.warn{border-left-color:var(--warn);background:var(--warn-card)}
details.check.fail{border-left-color:var(--fail);background:var(--fail-card)}
summary{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:12px;padding:15px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
.chip{padding:4px 9px;border-radius:999px;font-size:11px;font-weight:800;text-align:center;min-width:74px}
.chip.ok{background:var(--ok-bg);color:var(--ok)}
.chip.warn{background:var(--warn-bg);color:var(--warn)}
.chip.fail{background:var(--fail-bg);color:var(--fail)}
.check-copy{min-width:0}
.name{display:block;font-weight:700;font-size:14px}
.msg{display:block;margin-top:2px;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.cat-tag{display:inline-block;margin-right:6px;font-size:10px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.05em}
.ms{color:var(--muted);font-family:var(--mono);font-size:11px}
.check-body{padding:0 16px 16px 16px}
ul.d{margin:0 0 12px 0;padding:0 0 0 20px;color:var(--ink);font:12px/1.65 var(--mono);overflow-wrap:anywhere}
.quick-fix{display:flex;align-items:center;gap:10px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font:12px var(--mono)}
.quick-fix code{flex:1;overflow-x:auto;color:var(--warn);white-space:nowrap}
.copy-btn{padding:3px 8px;border:1px solid var(--line);border-radius:4px;background:var(--surface);color:var(--ink);font-size:11px;cursor:pointer}
.copy-btn:hover{border-color:var(--accent)}

.login-shell{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,420px);gap:clamp(30px,6vw,80px);align-items:center;width:min(1040px,calc(100% - 40px));min-height:100vh;margin:auto;padding:40px 0}
.login-intro h1{font-size:clamp(30px,4.5vw,48px);line-height:1.1;letter-spacing:-.04em;margin:0 0 14px}
.login-intro p{color:var(--muted);font-size:16px;margin:0 0 24px}
.login{padding:28px;border:1px solid var(--line);border-radius:14px;background:var(--surface);box-shadow:var(--shadow)}
.login input[type=password]{width:100%;margin:8px 0 14px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
.login .primary{width:100%;padding:10px;border:1px solid var(--accent);border-radius:8px;background:var(--accent);color:#fff;font-weight:700}
.err{color:var(--fail);margin:0 0 12px;font-size:13px}

@media(max-width:980px){.app-shell{grid-template-columns:1fr}.sidebar{display:none}.checks{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.login-shell{grid-template-columns:1fr}}
</style>
</head>
<body>
<?php if (!$authed): ?>
  <div class="login-shell">
    <section class="login-intro">
      <div class="brand"><span class="brand-mark">⚡</span><span><?= $e($cfg['app_name'] ?? 'DevSentinel') ?><small>Technician Workbench</small></span></div>
      <h1>Diagnostic & Observability Workbench</h1>
      <p>Proactive hardware, runtime, database, security, and Git telemetry for software developers and IT technicians.</p>
      <div style="display:grid;gap:10px;color:var(--muted);font-size:14px">
        <div>✓ Cross-platform hardware & resource metrics (Windows, Linux, macOS)</div>
        <div>✓ Polyglot runtime checks (PHP, Node.js, Python, Docker)</div>
        <div>✓ Database & Redis latency and schema health</div>
        <div>✓ Code security, secrets scanner, and dependency CVE auditing</div>
      </div>
    </section>
    <form class="login" method="post" autocomplete="off">
      <h2 style="margin:0 0 6px;font-size:20px">Technician Sign-in</h2>
      <p style="margin:0 0 16px;color:var(--muted);font-size:13px">Enter dashboard master password</p>
      <?php if ($error): ?><p class="err"><?= $e($error) ?></p><?php endif; ?>
      <input type="hidden" name="csrf" value="<?= $e($csrf) ?>">
      <input type="hidden" name="action" value="login">
      <label for="pw" style="font-size:13px;font-weight:600">Password</label>
      <input id="pw" type="password" name="password" required autofocus placeholder="••••••••••••">
      <button class="primary" type="submit">Unlock Workbench</button>
    </form>
  </div>
<?php else: ?>
<div class="app-shell">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark">⚡</span><span><?= $e($cfg['app_name'] ?? 'DevSentinel') ?><small>DevOps & SRE</small></span></div>
    <p class="nav-label">Workbench</p>
    <nav>
      <a class="active" href="#overview"><span>▦</span> All Diagnostics</a>
      <a href="#system" onclick="filterCategory('system')"><span>🖥️</span> System & OS</a>
      <a href="#runtime" onclick="filterCategory('runtime')"><span>🚀</span> Runtimes</a>
      <a href="#database" onclick="filterCategory('database')"><span>🗄️</span> Databases</a>
      <a href="#security" onclick="filterCategory('security')"><span>🛡️</span> Security & Secrets</a>
      <a href="#devops" onclick="filterCategory('devops')"><span>📦</span> DevOps & Git</a>
      <a href="#logs" onclick="filterCategory('logs')"><span>📜</span> Error Logs</a>
    </nav>
    <div class="side-card">
      <strong><span class="pulse"></span>Monitoring Active</strong>
      <small>Host: <?= $e(gethostname()) ?></small>
      <small>Platform: <?= $e(PHP_OS . ' ' . php_uname('m')) ?></small>
    </div>
  </aside>

  <main class="workspace" id="overview">
    <header class="topbar">
      <div>
        <span class="eyebrow">Diagnostic Workbench</span>
        <h1><?= $e($cfg['app_name'] ?? 'DevSentinel') ?> Overview</h1>
      </div>
      <form class="actions" method="post">
        <input type="hidden" name="csrf" value="<?= $e($csrf) ?>">
        <button class="theme-toggle" type="button" data-theme-toggle>Theme</button>
        <a href="?json=1" target="_blank" class="theme-toggle" style="text-decoration:none;display:inline-block">Raw JSON</a>
        <button class="primary" name="action" value="scan" type="submit">Run Diagnostics</button>
        <button name="action" value="logout" type="submit">Sign Out</button>
      </form>
    </header>

    <?php if (!$report): ?>
      <div class="panel"><strong>No diagnostic report on file.</strong> Click <strong>Run Diagnostics</strong> above or execute <code>php cli.php doctor</code>.</div>
    <?php else: ?>
      <section class="hero <?= $e($report['overall']) ?>">
        <div>
          <span class="eyebrow">Fleet Health Status</span>
          <h3><?= $e($headline) ?></h3>
          <p>Scan completed at <?= $e(date('Y-m-d H:i:s', strtotime($report['time']))) ?></p>
          <div class="hero-badges">
            <span class="badge">Host: <?= $e($report['host'] ?? 'unknown') ?></span>
            <span class="badge">OS: <?= $e($report['os'] ?? PHP_OS) ?></span>
            <span class="badge">Total Probes: <?= $totalChecks ?></span>
          </div>
        </div>
        <span class="hero-mark"><?= $report['overall'] === 'ok' ? '✓' : '!' ?></span>
      </section>

      <section class="stats">
        <article class="stat"><span class="stat-label">Total Checks</span><strong class="stat-value"><?= $totalChecks ?></strong><span class="stat-note">Across all subsystems</span></article>
        <article class="stat"><span class="stat-label">Passed</span><strong class="stat-value ok"><?= $statusCounts['ok'] ?></strong><span class="stat-note">Subsystems healthy</span></article>
        <article class="stat"><span class="stat-label">Warnings</span><strong class="stat-value warn"><?= $statusCounts['warn'] ?></strong><span class="stat-note">Action recommended</span></article>
        <article class="stat"><span class="stat-label">Critical</span><strong class="stat-value fail"><?= $statusCounts['fail'] ?></strong><span class="stat-note">Technician fix needed</span></article>
      </section>

      <?php if ($history): ?>
        <section class="panel">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <strong style="font-size:14px">Telemetry History (Last <?= count($history) ?> Scans)</strong>
            <span class="cap">Chronological timeline</span>
          </div>
          <div class="strip">
            <?php foreach ($history as $h): ?>
              <i class="<?= $e($h['overall']) ?>" title="<?= $e($h['time']) ?>: <?= $e(strtoupper($h['overall'])) ?>"></i>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endif; ?>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Incident Summary</h2>
            <p class="panel-note"><?= $incidentFindings ? $e($incidentSummaryText) : 'No unresolved findings in the latest diagnostic report.' ?></p>
          </div>
          <?php if ($incidentSummaryText): ?><button type="button" class="copy-btn" onclick="copyText('incident-summary-text', this)">Copy summary</button><?php endif; ?>
        </div>
        <?php if ($incidentGroups): ?>
          <div class="finding-groups">
            <?php foreach ($incidentGroups as $category => $findings): ?>
              <div class="finding-group">
                <strong><?= $e($category) ?> · <?= count($findings) ?> finding(s)</strong>
                <?php foreach ($findings as $finding): ?>
                  <a href="#check-<?= (int) $finding['index'] ?>"><?= $e(strtoupper($finding['status'])) ?>: <?= $e($finding['name']) ?></a>
                <?php endforeach; ?>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
        <div class="summary-copy">
          <textarea id="incident-summary-text" readonly><?= $e($incidentSummaryText ?: 'No unresolved diagnostic findings.') ?></textarea>
        </div>
        <?php if ($incidentFindings): ?><p class="panel-note">Start with critical failures; use each linked check for its details and remediation. Review warnings after immediate service impact is addressed.</p><?php endif; ?>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Learning Service History</h2>
            <p class="panel-note">Recent health status, response time, and state transitions.</p>
          </div>
        </div>
        <?php if ($learningHistory): ?>
          <div class="audit-table-wrap">
            <table class="audit-table">
              <thead><tr><th>Time</th><th>Status</th><th>Probe</th><th>Transition</th></tr></thead>
              <tbody>
              <?php foreach (array_slice($learningHistory, 0, 10) as $entry): ?>
                <tr>
                  <td><?= $e(date('Y-m-d H:i:s', strtotime($entry['time']))) ?></td>
                  <td><span class="state-tag <?= $e($entry['status']) ?>"><?= $e($entry['status']) ?></span></td>
                  <td><?= (int) $entry['ms'] ?> ms</td>
                  <td><?= $e($entry['transition'] ?: 'No state change') ?></td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php else: ?>
          <p class="panel-note">No health observations have been recorded yet. Run diagnostics to begin a bounded local history.</p>
        <?php endif; ?>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Dashboard Authentication Events</h2>
            <p class="panel-note">Read-only view. Passwords are never stored. At most 1,000 recent events are retained.</p>
          </div>
          <a class="copy-btn" href="?auth_export=csv&amp;auth_event=<?= $e(rawurlencode($authEventFilter)) ?>&amp;auth_minutes=<?= $authWindowMinutes ?>">Export filtered CSV</a>
        </div>
        <form class="inline-form" method="get">
          <label for="auth-event-filter">Event</label>
          <select id="auth-event-filter" name="auth_event">
            <option value="all" <?= $authEventFilter === 'all' ? 'selected' : '' ?>>All events</option>
            <?php foreach ($authEventTypes as $eventType): ?>
              <option value="<?= $e($eventType) ?>" <?= $authEventFilter === $eventType ? 'selected' : '' ?>><?= $e(str_replace('_', ' ', $eventType)) ?></option>
            <?php endforeach; ?>
          </select>
          <label for="auth-window-filter">Time window</label>
          <select id="auth-window-filter" name="auth_minutes">
            <?php foreach ([15, 60, 360, 1440, 10080] as $minutes): ?>
              <?php $windowLabel = match ($minutes) { 15 => '15 minutes', 60 => '1 hour', 360 => '6 hours', 1440 => '1 day', 10080 => '7 days' }; ?>
              <option value="<?= $minutes ?>" <?= $authWindowMinutes === $minutes ? 'selected' : '' ?>>Last <?= $windowLabel ?></option>
            <?php endforeach; ?>
          </select>
          <button type="submit">Apply filters</button>
        </form>
        <?php if ($authEvents === null): ?>
          <p class="panel-note">Audit events could not be read. Check data_dir permissions and the audit log path.</p>
        <?php elseif (!$authEvents): ?>
          <p class="panel-note">No matching authentication events in this time window.</p>
        <?php else: ?>
          <div class="audit-table-wrap">
            <table class="audit-table">
              <thead><tr><th>Time</th><th>Event</th><th>Source IP</th><th>User agent</th></tr></thead>
              <tbody>
              <?php foreach ($authEvents as $event): ?>
                <tr>
                  <td><?= $e(date('Y-m-d H:i:s', strtotime($event['time']))) ?></td>
                  <td><?= $e(str_replace('_', ' ', $event['event'])) ?></td>
                  <td><?= $e($event['ip']) ?></td>
                  <td><?= $e($event['user_agent']) ?></td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </section>

      <?php if (!empty($cfg['demo_scenarios_enabled'])): ?>
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2>Safe Demo Incident Scenarios</h2>
              <p class="panel-note">Previews only; scenarios do not stop services, open ports, change firewall rules, or write fake login events.</p>
            </div>
          </div>
          <div class="scenario-grid">
            <?php foreach ($demoScenarios as $scenarioKey => $scenario): ?>
              <form class="scenario-form" method="post">
                <input type="hidden" name="csrf" value="<?= $e($csrf) ?>">
                <input type="hidden" name="action" value="demo_scenario">
                <input type="hidden" name="scenario" value="<?= $e($scenarioKey) ?>">
                <button type="submit"><?= $e($scenario['title']) ?></button>
              </form>
            <?php endforeach; ?>
          </div>
          <?php if ($activeDemoScenario): ?>
            <div class="scenario-preview">
              <div class="panel-head">
                <h3><span class="state-tag <?= $e($activeDemoScenario['status']) ?>">SIMULATED</span> <?= $e($activeDemoScenario['title']) ?></h3>
                <form method="post">
                  <input type="hidden" name="csrf" value="<?= $e($csrf) ?>">
                  <input type="hidden" name="action" value="clear_demo_scenario">
                  <button class="copy-btn" type="submit">Clear preview</button>
                </form>
              </div>
              <strong><?= $e($activeDemoScenario['message']) ?></strong>
              <ul>
                <?php foreach (array_merge($activeDemoScenario['details'], $activeDemoScenario['next']) as $scenarioLine): ?>
                  <li><?= $e($scenarioLine) ?></li>
                <?php endforeach; ?>
              </ul>
            </div>
          <?php else: ?>
            <p class="panel-note">Choose a scenario to preview a technician workflow. The selection is stored only in your session and can be cleared.</p>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <!-- Category Tabs for Developer Technicians -->
      <div class="category-tabs">
        <button class="tab-btn active" onclick="filterCategory('all', this)">All Checks (<?= $totalChecks ?>)</button>
        <button class="tab-btn" onclick="filterCategory('system', this)">🖥️ System</button>
        <button class="tab-btn" onclick="filterCategory('runtime', this)">🚀 Runtime</button>
        <button class="tab-btn" onclick="filterCategory('database', this)">🗄️ Database</button>
        <button class="tab-btn" onclick="filterCategory('security', this)">🛡️ Security</button>
        <button class="tab-btn" onclick="filterCategory('devops', this)">📦 DevOps & Git</button>
        <button class="tab-btn" onclick="filterCategory('logs', this)">📜 Logs</button>
      </div>

      <section id="checks">
        <ul class="checks">
          <?php foreach ($report['checks'] as $checkIndex => $c): ?>
            <li data-cat="<?= $e($c['category'] ?? 'general') ?>">
              <details class="check <?= $e($c['status']) ?>" id="check-<?= (int) $checkIndex ?>" <?= $c['status'] !== 'ok' ? 'open' : '' ?>>
                <summary>
                  <span class="chip <?= $e($c['status']) ?>"><?= $e(strtoupper($c['status'])) ?></span>
                  <span class="check-copy">
                    <span class="name"><span class="cat-tag"><?= $e($c['category'] ?? '') ?></span><?= $e($c['name']) ?></span>
                    <span class="msg"><?= $e($c['message']) ?></span>
                  </span>
                  <span class="ms"><?= (int) $c['ms'] ?> ms</span>
                </summary>
                <div class="check-body">
                  <?php if (!empty($c['details'])): ?>
                    <ul class="d">
                      <?php foreach ($c['details'] as $line): ?>
                        <li><?= $e($line) ?></li>
                      <?php endforeach; ?>
                    </ul>
                  <?php endif; ?>
                  <?php if (!empty($c['remediation'])): ?>
                    <div class="quick-fix">
                      <span style="font-weight:700">💡 Fix:</span>
                      <code><?= $e($c['remediation']) ?></code>
                      <button type="button" class="copy-btn" onclick="copyFix(this, '<?= $e(addslashes($c['remediation'])) ?>')">Copy</button>
                    </div>
                  <?php endif; ?>
                </div>
              </details>
            </li>
          <?php endforeach; ?>
        </ul>
      </section>
    <?php endif; ?>
  </main>
</div>
<?php endif; ?>

<script>
function filterCategory(cat, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const items = document.querySelectorAll('.checks li');
  items.forEach(item => {
    if (cat === 'all' || item.getAttribute('data-cat') === cat) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
    }
  });
}

function copyFix(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = original; }, 1800);
  });
}

function copyText(id, btn) {
  const field = document.getElementById(id);
  if (!field) return;
  navigator.clipboard.writeText(field.value).then(() => {
    const original = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = original; }, 1800);
  });
}
</script>
<script src="theme.js" defer></script>
</body>
</html>
