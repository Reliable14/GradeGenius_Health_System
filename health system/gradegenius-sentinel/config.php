<?php
declare(strict_types=1);

/**
 * DevSentinel Configuration
 * Health, Security, and Observability Workbench for Software Developer Technicians.
 *
 * Environment variables can override sensitive fields:
 * SENTINEL_DB_USER, SENTINEL_DB_PASS, SENTINEL_PASSWORD_HASH, SENTINEL_WEBHOOK, SENTINEL_API_TOKEN
 */
return [
    // Set APP_ENV=demo only for a local demo deployment; demo scenarios are disabled here.
    'environment' => getenv('APP_ENV') ?: 'production',
    // Name of the service or application being monitored
    'app_name' => 'DevSentinel Platform',

    // Absolute path to the application codebase to inspect (PHP, Node.js, Python, etc.)
    'app_root' => realpath(__DIR__ . '/../demo-app') ?: __DIR__ . '/../demo-app',

    // Public web URL of the service (tested for HTTP response, SSL certificate expiry, security headers)
    'app_url'  => 'https://example.com',
    // Optional private health URL returning JSON {status, components}; do not include credentials in the URL.
    'learning_health_url' => getenv('SENTINEL_LEARNING_HEALTH_URL') ?: '',
    'auth_audit_window_minutes' => max(1, (int) (getenv('SENTINEL_AUTH_AUDIT_WINDOW_MINUTES') ?: 60)),
    // Keep a bounded local history of learning service state and response time.
    'learning_health_history_limit' => 200,
    'demo_scenarios_enabled' => false,
    'public_tcp_ports' => [80, 443],

    // Directory where reports, history, and the integrity baseline are persisted
    'data_dir' => __DIR__ . '/data',

    // Directory containing custom executable scripts/probes (*.sh, *.php, *.ps1)
    'custom_checks_dir' => __DIR__ . '/checks.d',

    // Runtimes & Dependencies
    'php_cli'  => 'php',
    'min_php'  => '8.1.0',
    'required_extensions' => ['pdo', 'json'],

    // Dashboard Authentication (generate hash via: php cli.php make-password)
    'dashboard_password_hash' => getenv('SENTINEL_PASSWORD_HASH') ?: '',
    'dashboard_allowed_ips'   => [], // Optional IP allowlist: e.g. ['127.0.0.1', '192.168.1.50']
    'api_token'               => getenv('SENTINEL_API_TOKEN') ?: '', // Used for Prometheus / Uptime monitors

    // Relational Database Connectivity (MySQL, PostgreSQL, SQLite)
    'db' => [
        // MySQL example:      'mysql:host=127.0.0.1;dbname=app_db;charset=utf8mb4'
        // PostgreSQL example: 'pgsql:host=127.0.0.1;port=5432;dbname=app_db'
        // SQLite example:     'sqlite:/var/www/app/database/database.sqlite'
        'dsn'     => getenv('SENTINEL_DB_DSN') ?: '',
        'user'    => getenv('SENTINEL_DB_USER') ?: '',
        'pass'    => getenv('SENTINEL_DB_PASS') ?: '',
        'slow_ms' => 500, // Warn if ping latency exceeds this threshold
        'required_tables' => [], // e.g. ['users', 'migrations']
    ],

    // In-memory Cache & Queue (Redis / KeyDB)
    'redis' => [
        'host'    => getenv('REDIS_HOST') ?: '', // e.g. '127.0.0.1' (leave blank to skip)
        'port'    => (int) (getenv('REDIS_PORT') ?: 6379),
        'timeout' => 2.0,
    ],

    // Linux System Services to monitor via systemctl is-active (Linux only)
    'monitored_services' => ['nginx', 'docker', 'redis-server', 'supervisor'],

    // Sensitive local TCP ports to audit (detect exposed databases or debug ports).
    'audit_internal_ports' => [
        6379  => 'Redis',
        27017 => 'MongoDB',
        9200  => 'Elasticsearch',
        9229  => 'Node.js Inspector',
    ],

    // Log files to analyze for fatal exceptions, SQL errors, and auth brute-force
    'log_files' => [
        __DIR__ . '/../demo-app/storage/logs/app.log',
    ],
    'log_window_minutes' => 60,

    // Code & Security Scanning exclusions
    'scan_exclude_dirs'    => ['vendor', 'node_modules', '.git', 'storage', 'cache', 'uploads', 'data'],
    'scan_ignore_files'    => [],
    'max_files'            => 1500,
    'integrity_extensions' => ['php', 'phtml', 'js', 'ts', 'py', 'htaccess', 'ini', 'json'],

    // Alert & Diagnostic Thresholds
    'thresholds' => [
        'disk_warn'      => 80,
        'disk_fail'      => 90,
        'mem_warn'       => 85,
        'mem_fail'       => 95,
        'load_warn'      => 1.0,  // Load average per CPU core
        'load_fail'      => 2.0,
        'http_slow_ms'   => 2000,
        'log_fatal_fail' => 10,
        'log_warn_warn'  => 50,
        'log_auth_warn'  => 15,
        'log_auth_fail'  => 50,
        'auth_ip_warn'   => 5,
        'auth_ip_fail'   => 20,
    ],

    // Notifications (Email & Webhooks for Slack, Discord, MS Teams, PagerDuty)
    'alerts' => [
        'email'            => [],
        'from'             => 'sentinel@example.com',
        'webhook'          => getenv('SENTINEL_WEBHOOK') ?: '',
        'dashboard_url'    => '',
        'cooldown_minutes' => 60,
    ],
];
