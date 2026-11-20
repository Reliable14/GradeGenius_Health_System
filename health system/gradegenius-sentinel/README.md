# DevSentinel - Technician & Developer Diagnostic Workbench

A modular, lightweight, and cross-platform health, security, and observability workbench designed specifically for **software developers, IT technicians, SREs, and DevOps teams**.

It monitors host infrastructure, multi-stack runtimes, databases, security configurations, Git deployment drift, and application logs — and provides **actionable copy-paste remediation commands** for every detected issue.

---

## 🚀 Key Subsystems & Checks

| Category | Diagnostic Probes | What It Catches & Solves |
|---|---|---|
| **🖥️ System Resources** | RAM, CPU, Load Average, Disk Usage | Memory leaks, runaway processes, full partitions, CPU saturation across Windows, Linux, and macOS. |
| **🚀 Runtime & Deps** | PHP, Node.js, Python, Composer & NPM | Vulnerable packages (`composer audit`, `npm audit`), obsolete runtimes, dangerous `php.ini` flags (`display_errors`, `allow_url_include`). |
| **🗄️ Databases & Caches** | MySQL, PostgreSQL, SQLite, Redis / KeyDB | Connection latency, slow queries, missing schema tables, SQLite file corruption (`PRAGMA integrity_check`), Redis queue ping. |
| **🛡️ Network & Web Security** | HTTP status, SSL certificate, Security Headers, Exposed Ports | SSL expiration (<7d / <21d), missing HSTS/CSP/X-Frame-Options, exposed `/.env` or `/.git`, open internal ports (Redis 6379, Mongo 27017, Debug 9229). |
| **🎓 Learning Service Health** | Configured health endpoint, response time, and bounded state history | Reports whether the learning API and listed workers/dependencies are active, degraded, or down, and highlights state transitions. |
| **🔐 Dashboard Login Audit** | Failed sign-ins, lockouts, source IP and user agent | Highlights repeated attempts by source IP. Passwords are never stored; authorized dashboard users can filter and export recent events. |
| **🔌 Listening Ports & Exposure** | Local TCP listener inventory, process names, and available host firewall state | Flags risky listeners such as SMB, MySQL, Redis, MongoDB, Docker API, and debug ports bound beyond loopback; it does not scan remote hosts or modify firewall rules. |
| **🧰 Production Readiness** | Dashboard credentials, HTTPS URL, health route, data directory, logs, monitored services, and alert destinations | Highlights configuration gaps before production use without printing secret values. |
| **🛡️ Code & Secrets** | Syntax linting (`php -l`), Secret scanning | Leaked private keys (`BEGIN PRIVATE KEY`), AWS/GCP/GitHub access tokens in code, injection risks (`eval`, unescaped SQL, dynamic inclusions). |
| **📦 DevOps & Git** | Git repo status, Docker & PM2, Systemd | Dirty production workspaces, uncommitted hotfixes, crashed Docker containers (`exited(1)`), failed PM2 workers, dead systemd daemons. |
| **📦 File Integrity** | Cryptographic SHA-256 tree comparison | Detects any unauthorized file creations, modifications, or deletions since last deployment baseline. |
| **📜 Logs & Errors** | Application & web server logs tailing | Bursts of fatal errors, uncaught exceptions, SQLSTATE failures, and authentication brute-force attempts. |
| **🔌 Custom Probes** | Drop-in scripts in `checks.d/` | Run any custom technician script (`*.sh`, `*.php`, `*.ps1`, `*.py`) with exit-code based health reporting. |

---

## 🛠️ Developer Technician CLI

DevSentinel includes a powerful command-line interface tailored for developers and terminal SSH sessions:

```bash
# Interactive Technician Doctor (rich ANSI colors, category grouping, and Quick Fix commands)
php cli.php doctor

# Standard CI/CD runner (Exit 0=OK, 1=WARN, 2=FAIL)
php cli.php run
php cli.php run -v

# Deep Security & Vulnerability Audit
php cli.php audit

# Raw JSON output for pipelines, Prometheus, or Datadog
php cli.php json

# Establish or refresh the trusted file baseline after a deploy
php cli.php baseline

# Generate a secure dashboard authentication password hash
php cli.php make-password
```

---

## 💡 Actionable Quick-Fix Guidance

DevSentinel doesn't just display failures; it tells technicians **how to fix them immediately**:

* **World-readable `.env`:** `chmod 640 .env`
* **Exposed `display_errors`:** `Edit php.ini: set display_errors = Off`
* **Vulnerable packages:** `npm audit fix` / `composer audit`
* **SSL Expiring:** `certbot renew`
* **Dirty Production Git State:** `git status` / `git stash`

---

## 🔌 Custom Technician Probes (`checks.d/`)

Add any custom probe in seconds. Simply place an executable script inside `checks.d/`:

* **Exit Code `0`:** OK / Passed
* **Exit Code `1`:** Warning
* **Exit Code `>= 2`:** Failure / Alert

Example (`checks.d/check-queue.php`):
```php
<?php
// Custom probe checking message queue backlog
$backlog = 12; // Fetch from RabbitMQ/Redis
if ($backlog > 500) {
    echo "Queue backlog critical: {$backlog} jobs waiting";
    exit(2);
}
echo "Queue healthy: {$backlog} jobs in queue";
exit(0);
```

---

## 📊 Web Dashboard

A responsive dark/light developer dashboard is included in `public/index.php`:
* **Category Tabs**: Filter between All, System, Runtime, Database, Security, DevOps, and Logs.
* **1-Click Copy Fix**: Copy remediation terminal commands directly to clipboard.
* **Timeline Strip**: Historical health of the last 48 diagnostic runs.
* **Incident Summary**: Groups failing and warning checks by subsystem and links to the affected diagnostic cards.
* **Safe Demo Scenarios**: Local previews for a learning outage, a login burst, and risky listeners; they do not change services, firewall rules, open ports, or auth logs.
* **Learning Health History**: Bounded local record of recent status transitions and response times in `data_dir/learning-health.jsonl`.
* **Authentication Event Export**: Filter the latest bounded dashboard audit events by event type and time window, then export CSV. The endpoint requires an authenticated dashboard session.
* **External Monitoring API**: Pass `X-Sentinel-Token: <token>` or `?token=<token>` to integrate with UptimeRobot, BetterUptime, or Prometheus.

### Quick Start Dashboard Server
```bash
# In the gradegenius-sentinel folder:
php -S 127.0.0.1:8082 -t public
```

---

## ⚙️ Configuration (`config.php`)

All checks are easily configured in `config.php`:
* `app_root`: Path to the monitored codebase.
* `app_url`: Public web endpoint.
* `learning_health_url`: Optional HTTP(S) health endpoint returning a small JSON status, for example `{"status":"active","components":{"learning_api":"active","queue":"degraded"}}`. Keep it private or access-controlled; never return secrets or stack traces.
* `APP_ENV`: Set to `demo` only for local demo deployments; demo incident previews are disabled unless explicitly enabled.
* `SENTINEL_AUTH_AUDIT_WINDOW_MINUTES`: Window used for repeated dashboard login attempt alerts.
* `learning_health_history_limit`: Maximum recent learning-health observations to retain (20-1000).
* `public_tcp_ports`: Local listener ports intentionally expected to be public (defaults to HTTP/HTTPS ports 80 and 443).
* `db`: DSN for MySQL, PostgreSQL, or SQLite.
* `redis`: Host and port for cache/queue ping.
* `monitored_services`: List of systemd services to watch on Linux.
* `audit_internal_ports`: List of sensitive internal ports to monitor.
* `alerts`: Email recipients and Slack/Discord/Teams webhook URLs.

Dashboard login events are saved to `data_dir/auth-events.jsonl` (or `auth_audit_file` if configured), capped to a recent bounded history, and contain only time, the direct connection's source IP, event type, and a shortened user-agent string. Submitted passwords and password hashes are never written to this log. `LogCheck` also summarizes failed application logins by IP when configured application logs include recognizable failure messages and source addresses. Behind a reverse proxy, correlate with trusted proxy logs rather than trusting a client-supplied forwarded-IP header. Protect `data_dir` from web access and restrict filesystem permissions.

Port exposure findings describe listeners on the Sentinel host. A wildcard or non-loopback bind is a risk signal, not proof that the service is internet-accessible; verify firewall, NAT, and cloud security-group rules before making changes.

The port check reports process names and firewall state only when local operating-system tools return usable information. It never changes listener bindings or firewall rules. The production-readiness probe is advisory except for a missing/invalid dashboard password hash or data/audit files stored inside the public web root. Demo incident previews are session-only and never write fabricated security events.
