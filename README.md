# Sentinel (Go) 👀

A lightweight server health monitoring daemon for [OpenPanel](https://github.com/stefanpejcic/OpenPanel/), written in Go for minimal resource usage and fast execution at high cron frequency (every 5 minutes or less).

Sentinel checks services, resource usage, logins, SSH activity, and DNS - sending email alerts when something goes wrong and attempting automatic recovery where possible.

---

## Installation

Requires Go 1.18 or newer.

```bash
# Clone or copy the source
cd /opt/sentinel

# Build
go mod init sentinel

# for AMD64 Linux
GOOS=linux GOARCH=amd64 go build -o sentinel-amd64

# for ARM64 Linux
GOOS=linux GOARCH=arm64 go build -o sentinel-arm64

# Verify
sentinel --debug
```

---

## Usage

```
opencli sentinel [--startup | --report | --debug]
```

| Flag | Description |
|---|---|
| *(no flag)* | Run full health check (intended for cron) |
| `--startup` | Send a reboot notification. Call this from a systemd service or `/etc/rc.local` on boot |
| `--report` | Send the daily usage report email |
| `--debug` | Print loaded configuration and debug info before running checks |

---

## What It Checks

### Services

Reads the `services=` list from `notifications.ini`. Supported values:

| Service key | What is checked |
|---|---|
| `caddy` | Docker container running + HTTP health check on port 80 |
| `csf` | systemd service active |
| `admin` | systemd service active (skips check if deliberately disabled via `/root/openadmin_is_disabled`) |
| `docker` | systemd service active |
| `panel` | `openpanel` Docker container running; starts it only if user accounts exist |
| `mysql` | `openpanel_mysql` Docker container running + responds to `SELECT 'PONG'` |
| `named` | `openpanel_dns` Docker container running; starts only if DNS zones exist |

For any service that is down, Sentinel attempts an automatic restart and logs the last 5–10 lines of error output before sending an alert.

---

### Login Monitoring

- **OpenAdmin logins** (`login=yes`)
  Reads `/var/log/openpanel/admin/login.log`. On each run, it checks whether the most recent login came from an IP address that has been seen before for that admin username. Sends an alert on first login from a new IP.
  Skips loopback (`127.0.0.1`) and invalid IPs automatically.
- **SSH logins** (`ssh=yes`)
  Reads currently active PTY sessions via `who`. Compares each IP against:
  1. `/etc/openpanel/openadmin/ssh_whitelist.conf` — supports individual IPs and CIDR ranges
  2. Previously seen IPs in the OpenAdmin login log (if an IP has logged into the admin panel, it is trusted for SSH too)
  If an active SSH session is from an unknown IP not on either list, an alert is sent.

---

### Resource Checks

All resource data is read directly from `/proc`:

| Check | Source | Default threshold | Behaviour when exceeded |
|---|---|---|---|
| Disk usage | `df` on `/` | 85% | Alert sent (deduplicated — no repeat until marked read) |
| System load | `/proc/loadavg` | 20 | Alert + crash log generated |
| RAM usage | `/proc/meminfo` | 85% | Alert sent (deduplicated) |
| CPU usage | `/proc/stat` (2-snapshot diff) | 90% | Alert + top processes attached |
| Swap usage | `/proc/meminfo` | 40% | Attempts automatic swap clear (`swapoff -a && swapon -a`), then re-checks and sends success or urgent failure alert |

The swap cleaner uses a lock file (`/tmp/swap_cleanup.lock`) to avoid running concurrent cleanup operations. The lock is considered stale after 6 hours.

---

### DNS Checks

Requires `dig` to be installed. Uses Google's public resolver (`8.8.8.8`) for all lookups.

- **Panel domain**: resolves the configured domain and checks it points to this server's public IP. Cloudflare-proxied domains are detected and skipped rather than flagged as failures.
- **Nameservers**: checks that NS1 and NS2 (and optionally NS3/NS4) resolve to one of this server's IPs. Warns if only one nameserver is configured.

The server's public IP is determined by querying `https://ip.openpanel.com` with fallback to `https://ipconfig.me`. If all external lookups fail, falls back to `ip addr`.

---

## Notifications

Notifications are written to `/var/log/openpanel/admin/notifications.log` in this format:

```
2025-10-14 08:32:01 UNREAD High CPU Usage! MESSAGE: CPU Usage: 94% | Top Processes: ...
```

The `UNREAD` marker means the notification has not been acknowledged in the OpenAdmin interface. Sentinel skips writing a new notification if an identical unread one already exists, preventing alert flooding across cron runs.

If an email address is configured in `openpanel.config`, Sentinel also POSTs the alert to the OpenAdmin email relay at `https://<domain>:2087/send_email` using a one-time security token. Supports HTTP Basic Auth if enabled in `admin.ini`.

---

## Configuration Files

- [`/etc/openpanel/openadmin/config/notifications.ini`](https://github.com/stefanpejcic/openpanel-configuration/blob/main/openadmin/config/notifications.ini)
  All thresholds must be integers between 1 and 100. Invalid values fall back to defaults.
- [`/etc/openpanel/openpanel/conf/openpanel.config`](https://github.com/stefanpejcic/openpanel-configuration/blob/main/openpanel/conf/openpanel.config)
  If `email` is empty, all email alerts are silently disabled. Notifications are still written to the log file.
- `/etc/openpanel/openadmin/ssh_whitelist.conf`
  One entry per line. Supports plain IPs and CIDR notation.

---

## Output

Each check prints one of:

```
[✔] Service is healthy
[!] Warning — non-critical issue
[✘] Failure — action taken or alert sent
```

At the end of each run a summary is printed:

```
------------------------------------------------------------
All Tests Passed!
------------------------------------------------------------
11 Tests PASSED
1 WARNINGS
0 Tests FAILED
------------------------------------------------------------
Elapsed time: 0.412 seconds
Memory usage: 4128 KB
```

Exit code is always `0` — failures are communicated via the log file and email alerts, not the process exit code (to avoid cron noise).

---

## File Locations

| Path | Purpose |
|---|---|
| `/etc/openpanel/openadmin/config/notifications.ini` | Check toggles and thresholds |
| `/etc/openpanel/openpanel/conf/openpanel.config` | Email, domain, nameserver config |
| `/etc/openpanel/openadmin/config/admin.ini` | Basic auth credentials for email relay |
| `/etc/openpanel/openadmin/ssh_whitelist.conf` | Trusted IPs/CIDRs for SSH check |
| `/var/log/openpanel/admin/notifications.log` | Notification log (read by OpenAdmin UI) |
| `/var/log/openpanel/admin/login.log` | OpenAdmin login history |
| `/var/log/openpanel/admin/crashlog/` | Crash reports generated on high load |
| `/tmp/swap_cleanup.lock` | Lock file for swap cleanup operation |
| `/root/openadmin_is_disabled` | If this file exists, the `admin` service check is skipped |

---

## Requirements

- Linux (reads `/proc` directly)
- Go 1.18+ to build
- `curl` — for email notifications and public IP lookup
- `dig` (`bind-utils` / `dnsutils`) — for DNS checks
- `docker` — for container checks
- `systemctl` — for service checks
- `opencli` — OpenPanel CLI tool (for domain and user queries)
- `swapoff` / `swapon` — for swap cleanup (typically in `util-linux`)

---

## MIT

Do whatever you want.
