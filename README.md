# RU mobile-internet whitelist -> sing-box rule-sets

Periodically mirrors the Russian mobile-internet whitelists from the upstream repo
into sing-box rule-set artifacts (JSON + .srs) and auto-deploys them to a GitHub repo.

Python standard library only (no pip dependencies; python-dotenv is used opportunistically).
sing-box is downloaded automatically from GitHub releases - no manual install needed.

## Two ways to run

    python sync_whitelist.py             # one check, then exit
    python sync_whitelist.py --daemon    # stay running, re-check every 24h

Daemon mode is meant to be started/stopped by an external service manager
(Task Scheduler, NSSM, systemd, docker...). The script just loops and handles
Ctrl+C / SIGTERM gracefully. Every check is idempotent: if the upstream lists
are unchanged (SHA-256 fingerprint in work/state.json) nothing is built or pushed.

## What one check does

1. Download whitelist.txt (SNI domains) and ipwhitelist.txt (IPs) from the source repo.
2. Compare SHA-256 against work/state.json; exit silently if unchanged.
3. Build rule-set sources:
   - whitelist-ru.json   -> {"version": 5, "rules": [{"domain_suffix": [...]}]}
   - ipwhitelist-ru.json -> {"version": 5, "rules": [{"ip_cidr": [...]}]}
4. Compile: sing-box rule-set compile --output X.srs X.json
   (sing-box auto-downloaded on first use, cached in work/bin/)
5. Clone DEPLOY_REPO, copy JSON + .srs, commit with a dated message, push.

Windows note: if git fails with "schannel: AcquireCredentialsHandle failed",
the script automatically retries with http.sslBackend=openssl.

## Requirements

- Python >= 3.8, git on PATH (used for deploy)
- Everything else (sing-box) is handled automatically
- GitHub PAT with Contents read/write on the destination repo

## Configuration

All via environment variables / .env (see .env.example). Key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| GH_PAT | - | GitHub PAT (required unless DRY_RUN=1) |
| DEPLOY_REPO | - | Destination repo owner/name (required) |
| DEPLOY_BRANCH | main | Branch to push to |
| DEPLOY_DIR | (root) | Subdirectory in the destination repo |
| SING_BOX_PATH | (auto) | Empty = download from SagerNet releases |
| SING_BOX_VERSION | latest | Pinned version, e.g. 1.14.0 |
| RULESET_VERSION | 5 | rule-set version field (5 needs sing-box >= 1.14) |
| DAEMON | 0 | 1 = same as --daemon |
| CHECK_INTERVAL_HOURS | 24 | Hours between checks in daemon mode |
| NO_COMPILE | 0 | 1 = JSON only, skip .srs |
| COMMIT_ON_CHANGES | 1 | 0 = stage only, never commit/push |
| DRY_RUN | 0 | 1 = no git/network writes |
| WORK_DIR | <script dir>/work | Cache dir (state.json, out/, bin/, deploy/) |

## Daily daemon setups

### Windows - Task Scheduler (auto-start at boot, runs continuously)

    powershell -ExecutionPolicy Bypass -File install_taskscheduler.ps1

Registers task "Sync-RU-Whitelist" which starts the daemon at logon/boot;
the script itself then loops every CHECK_INTERVAL_HOURS. Manage with:

    Start-ScheduledTask -TaskName Sync-RU-Whitelist      # start
    Stop-ScheduledTask -TaskName Sync-RU-Whitelist       # stop
    Unregister-ScheduledTask -TaskName Sync-RU-Whitelist # remove

### Windows - quick manual run

    python sync_whitelist.py --daemon

### Linux - systemd service

    # /etc/systemd/system/sync-whitelist.service
    [Unit]
    Description=RU whitelist sing-box rules sync
    After=network-online.target
    [Service]
    WorkingDirectory=/opt/singbox-whitelist
    Environment=GH_PAT=ghp_xxx
    Environment=DEPLOY_REPO=yourname/sing-box-src
    ExecStart=/usr/bin/python3 sync_whitelist.py --daemon
    Restart=on-failure
    [Install]
    WantedBy=multi-user.target

    systemctl enable --now sync-whitelist   # start + enable at boot
    systemctl stop sync-whitelist           # stop

## Example sing-box route usage

    {
      "route": {
        "rule_set": [
          { "type": "local", "tag": "ru-domains", "path": "whitelist-ru.srs" },
          { "type": "local", "tag": "ru-ips",     "path": "ipwhitelist-ru.srs" }
        ],
        "rules": [
          { "rule_set": ["ru-domains", "ru-ips"], "outbound": "direct" }
        ]
      }
    }

Or reference the deployed files directly from GitHub raw URLs (remote rule-set).

## Exit codes (single-run mode)

    0  success / nothing changed
    1  error (network / compile / git)
    2  no whitelist data could be fetched

## Files

    sync_whitelist.py          the worker script
    .env.example               environment variable template
    install_taskscheduler.ps1  Windows Task Scheduler helper (daemon at boot)
    work/                      cache: state.json, out/, bin/, deploy clone