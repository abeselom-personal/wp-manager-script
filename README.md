# wpcheck (WordPress Integrity + Uptime Kuma)

This repository contains a production-oriented Python script (`main.py`) that:

- Scans a server for WordPress installations (`wp-config.php` discovery).
- Verifies WordPress core integrity using WP-CLI (`wp core verify-checksums`).
- Performs **non-destructive remediation** by quarantining suspicious files (never deletes).
- Integrates with **Uptime Kuma v2** to ensure each domain has exactly:
  - `WP | <domain> | HTTP`
  - `WP | <domain> | CHECKSUM` (Push monitor)
- Sends Push heartbeats based on checksum results.

All logs are emitted as **JSON lines** (one JSON object per line) for easy ingestion into ELK/Loki/etc.

---

## Why “Option A” (systemd/cron env) is the best choice

Uptime Kuma monitor management is an **internal Socket.IO API**. In production, the most reliable and auditable approach is:

- Load secrets via **systemd EnvironmentFile**, cron environment, or your secrets manager.
- Keep application behavior explicit (no implicit `.env` loading inside the script).

This avoids surprises where running the same command in a different context loads different secrets.

> If you still want `.env` loading inside the script later, we can add it, but it’s intentionally not the default.

---

## Files

- `main.py`: The scanner + remediation + Kuma monitor reconciler.
- `.env`: **Local convenience** file (ignored by git). Not automatically loaded.
- `.env.example`: Template for environment variables.
- `requirements.txt`: Python dependencies.

---

## Prerequisites

### System requirements

- Linux server (script assumes WordPress lives under `/home/*/public_html` by default)
- Python 3.9+ recommended (works with newer Python as well)
- Root privileges are typical (the script assumes it may have access to all vhosts)

### WP-CLI

- WP-CLI must exist and be executable.
- Default path is `/usr/local/bin/wp` (override with `WPCHECK_WPCLI`).

Verify:

```bash
/usr/local/bin/wp --info
```

### Network / Uptime Kuma

- Your host must be able to reach the Kuma instance at `WPCHECK_KUMA_URL`.
- If Kuma is behind a reverse proxy, ensure **WebSocket upgrade is supported**, otherwise monitor CRUD (Socket.IO) may fail.

---

## Installation

### 1) Create and activate a virtual environment

On distros that enforce PEP 668 (externally managed Python), you must use a venv:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure environment variables

Copy the example:

```bash
cp .env.example .env
```

Edit `.env` and set values.

**Important:** the script does not auto-load `.env`.

For interactive shells you can load it with:

```bash
set -a
source .env
set +a
```

In production, use systemd EnvironmentFile or cron (examples below).

---

## Configuration reference

All configuration is provided via environment variables.

### Required

- `WPCHECK_KUMA_URL`
  - Example: `http://127.0.0.1:3001`
- `WPCHECK_KUMA_USER`
- `WPCHECK_KUMA_PASS`

### Common

- `WPCHECK_WPCLI` (default: `/usr/local/bin/wp`)
- `WPCHECK_HOME_DIR` (default: `/home`)
- `WPCHECK_CACHE_FILE` (default: `/wpcheck/kuma_cache.json`)
- `WPCHECK_IGNORE_FILE` (default: `/wpcheck/wp_checksum_ignore.txt`)
- `WPCHECK_QUARANTINE_DIR` (default: `/wpcheck/quarantine`)

### Kuma grouping (optional)

If group IDs are invalid or unset, monitors will be created without a parent.

- `WPCHECK_HTTP_GROUP_ID` (optional)
- `WPCHECK_CHECKSUM_GROUP_ID` (optional)

### Intervals / timeouts

- `WPCHECK_PUSH_INTERVAL` (default: `3600`)
- `WPCHECK_HTTP_INTERVAL` (default: `60`)
- `WPCHECK_HTTP_RETRIES` (default: `5`)
- `WPCHECK_REQUEST_TIMEOUT` (default: `15`)
- `WPCHECK_WP_TIMEOUT` (default: `120`)

### Concurrency

- `WPCHECK_WORKERS` (default: `8`)

### Safety / behavior flags

- `WPCHECK_DRY_RUN` (default: `false`)
- `WPCHECK_ENABLE_CORE_REDOWNLOAD` (default: `false`) 
  - If `true`, attempts `wp core download --force --skip-content` before quarantine remediation.
- `WPCHECK_QUARANTINE_SHOULD_NOT_EXIST` (default: `true`) 
  - If `true`, moves files reported as “should not exist” into quarantine.

### Ownership / cleanup

- `WPCHECK_TAKE_OWNERSHIP` (default: `false`)
  - If `true`, allows the script to “adopt” an existing monitor that matches the exact name but is not tagged as managed.
- `WPCHECK_DELETE_MANAGED_DUPLICATES` (default: `true`)
  - If `true`, deletes duplicate monitors *only* if they are tagged `managed_by=wpcheck`.
- `WPCHECK_CLEANUP_IGNORED` (default: `false`)
  - Enables deletion of **managed** monitors that correspond to ignored domains when running cleanup mode.

---

## Running

### Dry run (recommended first)

```bash
source venv/bin/activate
set -a; source .env; set +a
python main.py --dry-run
```

### Full run

```bash
source venv/bin/activate
set -a; source .env; set +a
python main.py
```

### Limit number of sites

```bash
python main.py --limit 10
```

### Cleanup mode (ignored domains)

This will delete **only wpcheck-managed** monitors for domains listed in `WPCHECK_IGNORE_FILE`.

```bash
python main.py --cleanup-only --cleanup-ignored
```

---

## Outputs and state

### Logs

- JSON lines to stdout.
- Redirect stdout/stderr to a log file when running via cron/systemd.

### Cache

- `WPCHECK_CACHE_FILE` stores:
  - monitor IDs
  - push token
  - site path
  - last seen timestamp

The cache is written atomically to reduce corruption risk.

### Quarantine

Suspicious files are moved to:

```
WPCHECK_QUARANTINE_DIR/<domain>/<timestamp>/<relative_path>
```

Nothing is deleted automatically.

---

## systemd (recommended)

### 1) Create an environment file

Example path:

- `/etc/wpcheck/wpcheck.env` (permissions **600**)

```ini
WPCHECK_KUMA_URL=http://127.0.0.1:3001
WPCHECK_KUMA_USER=admin
WPCHECK_KUMA_PASS=REDACTED
WPCHECK_WORKERS=12
```

### 2) Create a service

`/etc/systemd/system/wpcheck.service`:

```ini
[Unit]
Description=WordPress integrity check + Uptime Kuma integration
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/abeselom/CascadeProjects/windsurf-project
EnvironmentFile=/etc/wpcheck/wpcheck.env
ExecStart=/home/abeselom/CascadeProjects/windsurf-project/venv/bin/python /home/abeselom/CascadeProjects/windsurf-project/main.py
User=root

# Hardening (adjust if WP paths require broader access)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 3) Timer

`/etc/systemd/system/wpcheck.timer`:

```ini
[Unit]
Description=Run wpcheck hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now wpcheck.timer
systemctl list-timers | grep wpcheck
journalctl -u wpcheck.service -n 200 --no-pager
```

---

## Cron (alternative)

Example `/etc/cron.d/wpcheck`:

```cron
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WPCHECK_KUMA_URL=http://127.0.0.1:3001
WPCHECK_KUMA_USER=admin
WPCHECK_KUMA_PASS=REDACTED
WPCHECK_WORKERS=12

0 * * * * root /home/abeselom/CascadeProjects/windsurf-project/venv/bin/python /home/abeselom/CascadeProjects/windsurf-project/main.py >> /var/log/wpcheck.jsonl 2>&1
```

---

## Troubleshooting

### 1) “kuma_unreachable” or preflight failures

- Confirm Kuma URL is correct:
  - `curl -i http://<kuma>:3001/api/entry-page`
- Check firewall rules / routing.

### 2) Login failures (`kuma_login_failed`)

- Confirm credentials.
- If 2FA is enabled, set:
  - `WPCHECK_KUMA_2FA_TOKEN`

### 3) Monitor creation fails, Push works

This usually means **Socket.IO/WebSocket** is blocked.

- If behind Nginx/Traefik, ensure WebSocket upgrade headers are configured.
- Ensure Kuma is reachable via WebSocket:
  - Proxy must allow `Upgrade: websocket`.

### 4) WP-CLI timeouts (`wp_timeout`)

- Increase:
  - `WPCHECK_WP_TIMEOUT=180` (or more)
- Test manually:
  - `wp core verify-checksums --allow-root --skip-plugins --skip-themes`

### 5) Quarantine failures

- Ensure:
  - `WPCHECK_QUARANTINE_DIR` exists and is writable by the running user.
- Check for immutable files (`chattr +i`).

### 6) Cache corruption

If cache JSON becomes corrupted, the script will move it aside:

- `<cache>.corrupt.<timestamp>`

Then it will proceed with a fresh cache.

---

## Security notes

- Never commit `.env`.
- Prefer systemd EnvironmentFile with `chmod 600`.
- Consider using a secrets manager for `WPCHECK_KUMA_PASS`.

---

## Monitor naming contract

The script is intentionally strict to guarantee idempotency:

- HTTP: `WP | <domain> | HTTP`
- Push: `WP | <domain> | CHECKSUM`

Monitors are tagged via the `description` field:

- `managed_by=wpcheck;domain=<domain>;kind=<http|checksum>;wp_path=<path>`
