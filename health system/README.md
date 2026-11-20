# DevSentinel - Technician & Developer Diagnostic Workbench

A modular, cross-platform health, security, and observability system built for **software developers, IT technicians, SREs, and DevOps teams**.

---

## Architecture Overview

```
health system/
├── gradegenius-sentinel/           # DevSentinel Engine & Dashboard
│   ├── src/
│   │   ├── Sentinel.php           # Diagnostic orchestrator & alert dispatcher
│   │   ├── Contracts/
│   │   │   └── CheckInterface.php # Contract for modular diagnostic checks
│   │   ├── Platform/
│   │   │   └── OsHelper.php       # Cross-platform hardware metrics (Win/Linux/Mac)
│   │   └── Checks/
│   │       ├── SystemCheck.php    # CPU, RAM, Load, Disk telemetry
│   │       ├── RuntimeCheck.php   # PHP/Node/Python & vulnerability audits
│   │       ├── DatabaseCheck.php  # MySQL, Postgres, SQLite & Redis
│   │       ├── SecurityCheck.php  # SSL, HTTP headers, sensitive exposed files, ports
│   │       ├── CodeScanCheck.php  # Syntax lint, eval/SQLi patterns, leaked secrets
│   │       ├── GitCheck.php       # Branch, commit SHA, dirty workspace drift
│   │       ├── ProcessCheck.php   # Docker containers, PM2 apps, systemd services
│   │       ├── IntegrityCheck.php # SHA-256 cryptographic file tampering detector
│   │       ├── LogCheck.php       # Fatal exceptions, SQL errors, brute-force logins
│   │       └── CustomCheck.php    # Extensible checks.d/ probe loader
│   ├── checks.d/                  # Drop-in custom technician scripts (*.sh, *.php, *.ps1)
│   ├── config.php                 # Multi-stack configuration
│   ├── cli.php                    # Developer CLI (doctor, run, audit, json, baseline)
│   └── public/                    # Technician Web Console (dark/light theme)
└── demo-app/                      # Monitored target application
```

## Quick Start

### 1. Run Technician Doctor in Terminal
```powershell
cd gradegenius-sentinel
php cli.php doctor
```

### 2. Run Security & Secret Audit
```powershell
php cli.php audit
```

### 3. Launch Web Dashboard
```powershell
php -S 127.0.0.1:8082 -t public
# Open http://127.0.0.1:8082 in your browser
```
