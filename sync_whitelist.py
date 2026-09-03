#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sync_whitelist.py

Downloads the Russian mobile-internet whitelists from the source GitHub repo,
detects changes, builds sing-box rule-set sources (JSON, version 5) and
compiles them to binary (.srs), then deploys the changed files to a
destination GitHub repo using a PAT.

Two ways to run:

    python sync_whitelist.py             # one check, then exit
    python sync_whitelist.py --daemon    # stay running, re-check every 24h

The daemon mode is meant to be started/stopped by an external service
manager (systemd, Task Scheduler, NSSM, docker, ...); the script itself
just loops and handles SIGINT/SIGTERM gracefully.

sing-box is downloaded automatically from SagerNet/sing-box GitHub releases
for the current OS/architecture if SING_BOX_PATH is not provided.

Configuration (environment variables, see .env.example):

    GH_PAT              GitHub PAT (required unless DRY_RUN=1)
    SING_BOX_PATH       path to sing-box binary; if unset -> auto-download
    SING_BOX_VERSION    sing-box release to download, default "latest"
    SRC_REPO / SRC_BRANCH          source repo (default hxehex/... / main)
    DEPLOY_REPO / DEPLOY_BRANCH    destination repo and branch
    DEPLOY_DIR          subdirectory in the destination repo
    WORK_DIR            local cache dir (default <script dir>/work)
    RULESET_VERSION     rule-set "version" field (default: 5, sing-box >= 1.14)
    NO_COMPILE          1 = produce JSON only
    COMMIT_ON_CHANGES   1 = commit+push (default), 0 = stage only
    DRY_RUN             1 = no git/network writes
    DAEMON              1 = same as --daemon
    CHECK_INTERVAL_HOURS  hours between checks in daemon mode (default 24)
    GIT_USER / GIT_EMAIL           commit identity
    HTTP_TIMEOUT        download timeout seconds (default 60)
    LOG_FILE            log file (default <WORK_DIR>/sync.log)

Exit codes (single-run mode):
    0  success / nothing changed
    1  error
    2  no whitelist data could be fetched
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import urllib.request
import zipfile

SING_BOX_REPO = "SagerNet/sing-box"
USER_AGENT = "sync-whitelist/1.0"

try:
    from dotenv import load_dotenv  # optional
    load_dotenv()
except Exception:
    pass

stop_event = threading.Event()


def env(key, default=None):
    return os.environ.get(key) or default


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def utc_date():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def log(msg, log_path=None):
    line = "[" + now_iso() + "] " + msg
    try:
        print(line, flush=True)
    except Exception:
        pass
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


def fail(msg):
    log("FATAL: " + msg)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# http helpers
# --------------------------------------------------------------------------- #

def fetch_text(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def fetch_json(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_download(url, dest, timeout=300):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest + ".part"
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh, 1 << 20)
    os.replace(tmp, dest)
    return dest


# --------------------------------------------------------------------------- #
# parsing / rule-set sources
# --------------------------------------------------------------------------- #

def parse_lines(text):
    seen, out = set(), []
    for raw in text.splitlines():
        item = raw.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    out.sort()
    return out


def parse_ip_cidr(text, log_path=None):
    """ipwhitelist entries: plain IPs or CIDRs; invalid lines are skipped."""
    seen, out, skipped = set(), [], 0
    for item in parse_lines(text):
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            skipped += 1
            log("skipping invalid IP entry: " + item, log_path)
            continue
        out.append(item)
    return out, skipped


def make_domain_source(domains, version):
    # whitelist.txt holds SNI names; domain_suffix matches them + subdomains
    return {"version": version, "rules": [{"domain_suffix": domains}]}


def make_ip_source(ips, version):
    return {"version": version, "rules": [{"ip_cidr": ips}]}


# --------------------------------------------------------------------------- #
# sing-box: auto-download from GitHub releases
# --------------------------------------------------------------------------- #

def detect_go_platform():
    system = platform.system().lower()          # windows / linux / darwin
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("386", "i686", "i486", "i586", "i786"):
        arch = "386"
    elif machine.startswith("armv7") or machine == "armv6l":
        arch = "armv7"
    else:
        arch = "amd64"
    return system, arch


def latest_sing_box_version(timeout=30):
    data = fetch_json("https://api.github.com/repos/" + SING_BOX_REPO + "/releases/latest", timeout)
    tag = (data.get("tag_name") or "").lstrip("v")
    if not tag:
        raise RuntimeError("could not determine latest sing-box release")
    return tag


def ensure_sing_box(work_root, log_path=None, force=False):
    """Return a path to a working sing-box binary, downloading it if needed."""
    explicit = env("SING_BOX_PATH")
    if explicit and os.path.isfile(explicit):
        return explicit
    if explicit:
        log("SING_BOX_PATH does not exist (" + explicit + "); falling back to auto-download", log_path)

    bin_dir = os.path.join(work_root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    exe = "sing-box.exe" if platform.system().lower() == "windows" else "sing-box"
    cached = os.path.join(bin_dir, exe)
    if os.path.isfile(cached) and not force:
        return cached

    system, arch = detect_go_platform()
    version = env("SING_BOX_VERSION", "latest")
    if version.lower() == "latest":
        version = latest_sing_box_version()
    ext = "zip" if system == "windows" else "tar.gz"
    asset = "sing-box-{}-{}-{}.{}".format(version, system, arch, ext)
    url = "https://github.com/{}/releases/download/v{}/{}".format(SING_BOX_REPO, version, asset)

    log("downloading sing-box {} ({} / {}) ...".format(version, system, arch), log_path)
    log("  " + url, log_path)
    archive = http_download(url, os.path.join(bin_dir, asset))

    ok = False
    if ext == "zip":
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if os.path.basename(name).lower() == exe:
                    with zf.open(name) as src, open(cached, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    ok = True
                    break
    else:
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                if member.isfile() and os.path.basename(member.name) == "sing-box":
                    with tf.extractfile(member) as src, open(cached, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    ok = True
                    break
    try:
        os.remove(archive)
    except OSError:
        pass
    if not ok:
        fail("sing-box binary not found inside downloaded archive " + asset)
    if system != "windows":
        os.chmod(cached, 0o755)

    proc = subprocess.run([cached, "version"], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        fail("downloaded sing-box failed to run: " + proc.stderr.strip())
    log("sing-box ready: " + cached + " (" + proc.stdout.strip().splitlines()[0] + ")", log_path)
    return cached


def compile_srs(sing_box, source_json, output_srs, timeout=600):
    cmd = [sing_box, "rule-set", "compile", "--output", output_srs, source_json]
    log("running: " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        fail("sing-box binary not found at: " + sing_box)
    except subprocess.TimeoutExpired:
        fail("sing-box rule-set compile timed out")
    if proc.returncode != 0:
        fail("sing-box rule-set compile failed\nstdout: " + proc.stdout +
             "\nstderr: " + proc.stderr +
             "\n(hint: RULESET_VERSION=5 requires sing-box >= 1.14.0)")
    if not os.path.isfile(output_srs) or os.path.getsize(output_srs) == 0:
        fail("sing-box compile produced no output file: " + output_srs)


# --------------------------------------------------------------------------- #
# git deployment
# --------------------------------------------------------------------------- #

def _git_env():
    e = dict(os.environ)
    e["GIT_TERMINAL_PROMPT"] = "0"  # never hang the daemon on an auth prompt
    return e


def _is_schannel_error(stderr):
    s = (stderr or "").lower()
    return "schannel" in s or "sec_e_no_credentials" in s or "0x8009030e" in s


def git_cmd(cwd, *args):
    """Run git; on Windows schannel TLS failures retry with the openssl backend."""
    proc = subprocess.run(["git"] + list(args), cwd=cwd,
                          capture_output=True, text=True, env=_git_env())
    if proc.returncode != 0 and _is_schannel_error(proc.stderr):
        log("git hit a schannel error; retrying with http.sslBackend=openssl")
        proc = subprocess.run(["git", "-c", "http.sslBackend=openssl"] + list(args),
                              cwd=cwd, capture_output=True, text=True, env=_git_env())
    if proc.returncode != 0:
        fail("git " + args[0] + " failed\nstdout: " + proc.stdout + "\nstderr: " + proc.stderr)
    return proc


def run_git(cwd, *args):
    return git_cmd(cwd, *args)


def clone_deploy_repo(deploy_repo, deploy_branch, work_root, gh_pat, user_name, user_email):
    repo_dir = os.path.join(work_root, "deploy")
    os.makedirs(work_root, exist_ok=True)
    clone_url = "https://x-access-token:" + gh_pat + "@github.com/" + deploy_repo + ".git"
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        log("cloning " + deploy_repo + " -> " + repo_dir)
        proc = subprocess.run(["git", "clone", "--depth", "1", "--branch",
                               deploy_branch, clone_url, repo_dir],
                              capture_output=True, text=True, env=_git_env())
        if proc.returncode != 0 and _is_schannel_error(proc.stderr):
            log("retrying clone with http.sslBackend=openssl")
            proc = subprocess.run(["git", "-c", "http.sslBackend=openssl", "clone",
                                   "--depth", "1", "--branch", deploy_branch,
                                   clone_url, repo_dir],
                                  capture_output=True, text=True, env=_git_env())
        if proc.returncode != 0:
            fail("git clone failed: " + proc.stderr.strip())
    else:
        log("updating existing clone in " + repo_dir)
        run_git(repo_dir, "remote", "set-url", "origin", clone_url)
        run_git(repo_dir, "fetch", "origin", deploy_branch)
        run_git(repo_dir, "reset", "--hard", "origin/" + deploy_branch)
        run_git(repo_dir, "clean", "-fd")
    run_git(repo_dir, "config", "user.name", user_name)
    run_git(repo_dir, "config", "user.email", user_email)
    return repo_dir


def deploy_changes(repo_dir, deploy_branch, gh_pat, message, files):
    if not files:
        return
    run_git(repo_dir, "add", "--", *files)
    if not run_git(repo_dir, "status", "--porcelain").stdout.strip():
        log("nothing staged to commit")
        return
    run_git(repo_dir, "commit", "-m", message)
    log("pushing to origin/" + deploy_branch)
    proc = subprocess.run(["git", "push", "origin", "HEAD:" + deploy_branch],
                          cwd=repo_dir, capture_output=True, text=True, env=_git_env())
    if proc.returncode != 0 and _is_schannel_error(proc.stderr):
        log("retrying push with http.sslBackend=openssl")
        proc = subprocess.run(["git", "-c", "http.sslBackend=openssl", "push",
                               "origin", "HEAD:" + deploy_branch],
                              cwd=repo_dir, capture_output=True, text=True, env=_git_env())
    if proc.returncode != 0:
        fail("git push failed: " + proc.stderr.strip())


# --------------------------------------------------------------------------- #
# one check
# --------------------------------------------------------------------------- #

def run_once(cfg, log_path):
    # ---- 1. download source lists ------------------------------------------ #
    raw_base = "https://raw.githubusercontent.com/" + cfg["src_repo"] + "/" + cfg["src_branch"] + "/"
    sources = {"whitelist": raw_base + "whitelist.txt",
               "ipwhitelist": raw_base + "ipwhitelist.txt"}
    downloaded = {}
    for key, url in sources.items():
        try:
            downloaded[key] = fetch_text(url, cfg["http_timeout"])
            log("downloaded " + url + " (" + str(len(downloaded[key].encode("utf-8"))) + " bytes)", log_path)
        except Exception as exc:
            log("ERROR downloading " + url + ": " + repr(exc), log_path)

    if not downloaded:
        log("could not fetch any whitelist data", log_path)
        return 2

    # ---- 2. fingerprint & change detection ---------------------------------- #
    state_file = os.path.join(cfg["work_root"], "state.json")
    previous = {}
    if os.path.isfile(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as fh:
                previous = json.load(fh)
        except Exception:
            previous = {}

    changed = {}
    for key, text in downloaded.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if previous.get(key) != digest:
            changed[key] = digest
            log("changed: " + key, log_path)
        else:
            log("unchanged: " + key, log_path)
    if not changed:
        log("no changes detected; nothing to do", log_path)
        return 0

    # ---- 3. build rule-set sources (JSON, version 5) ------------------------- #
    out_dir = os.path.join(cfg["work_root"], "out")
    os.makedirs(out_dir, exist_ok=True)
    produced = []

    if "whitelist" in downloaded:
        domains = parse_lines(downloaded["whitelist"])
        path = os.path.join(out_dir, "whitelist-ru.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(make_domain_source(domains, cfg["rules_version"]), fh,
                      ensure_ascii=False, indent=2)
        produced.append(("whitelist-ru.json", path))
        log("wrote " + path + " (" + str(len(domains)) + " domains)", log_path)

    if "ipwhitelist" in downloaded:
        ips, skipped = parse_ip_cidr(downloaded["ipwhitelist"], log_path)
        if skipped:
            log("skipped " + str(skipped) + " invalid IP entries", log_path)
        path = os.path.join(out_dir, "ipwhitelist-ru.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(make_ip_source(ips, cfg["rules_version"]), fh,
                      ensure_ascii=False, indent=2)
        produced.append(("ipwhitelist-ru.json", path))
        log("wrote " + path + " (" + str(len(ips)) + " IPs)", log_path)

    # ---- 4. compile JSON -> .srs --------------------------------------------- #
    if cfg["do_compile"]:
        sing_box = ensure_sing_box(cfg["work_root"], log_path, force=cfg["singbox_force"])
        for (base, src_path) in list(produced):
            srs_path = os.path.join(out_dir, os.path.splitext(base)[0] + ".srs")
            compile_srs(sing_box, src_path, srs_path, cfg["http_timeout"])
            produced.append((os.path.basename(srs_path), srs_path))

    if cfg["dry_run"]:
        log("DRY_RUN: would deploy to " + cfg["deploy_repo"] + "/" + cfg["deploy_branch"], log_path)
        for (base, _p) in produced:
            log("  - " + base, log_path)
        with open(state_file, "w", encoding="utf-8") as fh:
            json.dump(dict(previous, **changed), fh, indent=2)
        return 0

    # ---- 5. deploy to github -------------------------------------------------- #
    if not cfg["gh_pat"]:
        log("GH_PAT is not set; cannot deploy (set DRY_RUN=1 to test)", log_path)
        return 1

    repo_dir = clone_deploy_repo(cfg["deploy_repo"], cfg["deploy_branch"],
                                 cfg["work_root"], cfg["gh_pat"],
                                 cfg["git_user"], cfg["git_email"])
    deploy_files = []
    for (base, src_path) in produced:
        rel = os.path.join(cfg["deploy_dir"], base) if cfg["deploy_dir"] else base
        dest = os.path.join(repo_dir, rel)
        os.makedirs(os.path.dirname(dest) or repo_dir, exist_ok=True)
        with open(src_path, "rb") as in_fh, open(dest, "wb") as out_fh:
            out_fh.write(in_fh.read())
        deploy_files.append(rel)
        log("staged: " + rel, log_path)

    counts = []
    if "whitelist" in downloaded:
        counts.append(str(len(parse_lines(downloaded["whitelist"]))) + " domains")
    if "ipwhitelist" in downloaded:
        ips, _ = parse_ip_cidr(downloaded["ipwhitelist"])
        counts.append(str(len(ips)) + " IPs")
    message = "Update RU whitelist (" + utc_date() + ", " + ", ".join(counts) + ")"

    if not cfg["do_commit"]:
        log("COMMIT_ON_CHANGES=0; files copied but not committed: " + ", ".join(deploy_files), log_path)
    else:
        deploy_changes(repo_dir, cfg["deploy_branch"], cfg["gh_pat"], message, deploy_files)
        log("deployed to https://github.com/" + cfg["deploy_repo"] + "/tree/" + cfg["deploy_branch"], log_path)

    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(dict(previous, **changed), fh, indent=2)
    return 0


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

def build_config(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    work_root = os.path.abspath(env("WORK_DIR", os.path.join(script_dir, "work")))
    os.makedirs(work_root, exist_ok=True)
    return {
        "gh_pat": env("GH_PAT") or env("GH_OAUTH_TOKEN"),
        "src_repo": env("SRC_REPO", "hxehex/russia-mobile-internet-whitelist"),
        "src_branch": env("SRC_BRANCH", "main"),
        "deploy_repo": env("DEPLOY_REPO"),
        "deploy_branch": env("DEPLOY_BRANCH", "main"),
        "deploy_dir": (env("DEPLOY_DIR", "") or "").strip("/\\"),
        "work_root": work_root,
        "rules_version": int(env("RULESET_VERSION", "5")),
        "do_compile": not (args.no_compile or env("NO_COMPILE", "0") == "1"),
        "singbox_force": env("SING_BOX_FORCE_DOWNLOAD", "0") == "1",
        "do_commit": env("COMMIT_ON_CHANGES", "1") == "1",
        "dry_run": env("DRY_RUN", "0") == "1",
        "git_user": env("GIT_USER", "whitelist-bot"),
        "git_email": env("GIT_EMAIL", "whitelist-bot@users.noreply.github.com"),
        "http_timeout": int(env("HTTP_TIMEOUT", "60")),
    }


def _handle_signal(signum, _frame):
    log("received signal " + str(signum) + ", shutting down")
    stop_event.set()


def main():
    ap = argparse.ArgumentParser(description="RU whitelist -> sing-box rule-sets sync")
    ap.add_argument("--daemon", action="store_true", help="keep running, re-check every interval")
    ap.add_argument("--once", action="store_true", help="single check then exit (default)")
    ap.add_argument("--interval", type=float, default=None, metavar="HOURS",
                    help="hours between checks in daemon mode (default 24)")
    ap.add_argument("--no-compile", action="store_true", help="skip .srs compilation")
    args = ap.parse_args()

    log_path = env("LOG_FILE") or os.path.join(
        os.path.abspath(env("WORK_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "work"))),
        "sync.log")
    cfg = build_config(args)

    if cfg["deploy_repo"] is None:
        fail("DEPLOY_REPO is not set (destination repository 'owner/name' required)")

    daemon = args.daemon or env("DAEMON", "0") == "1"

    if not daemon:
        log("=== sync_whitelist start ===", log_path)
        code = run_once(cfg, log_path)
        log("=== sync_whitelist done (exit " + str(code) + ") ===", log_path)
        sys.exit(code)

    interval = args.interval if args.interval else float(env("CHECK_INTERVAL_HOURS", "24"))
    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, OSError):
        pass

    log("=== sync_whitelist daemon started (interval: " + str(interval) + "h) ===", log_path)
    while not stop_event.is_set():
        try:
            code = run_once(cfg, log_path)
            if code:
                log("check finished with code " + str(code), log_path)
        except SystemExit as exc:
            log("check exited with code " + str(exc.code), log_path)
        except Exception as exc:
            log("check crashed: " + repr(exc), log_path)
        if stop_event.is_set():
            break
        log("next check in " + str(interval) + " hours", log_path)
        if stop_event.wait(interval * 3600):
            break
    log("=== sync_whitelist daemon stopped ===", log_path)


if __name__ == "__main__":
    main()
