#!/usr/bin/env python3
import os
import subprocess
import json
import argparse
import requests
import time
import sys
import shutil
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import socketio

# ---------------- CONFIG ----------------
def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _env_optional_int(name: str) -> Optional[int]:
    v = os.environ.get(name)
    if v is None:
        return None
    v = v.strip()
    if v == "" or v.lower() == "none":
        return None
    return int(v)


@dataclass(frozen=True)
class Config:
    wpcli: str
    home_dir: str
    cache_file: str
    ignore_file: str
    quarantine_dir: str
    kuma_url: str
    kuma_user: str
    kuma_pass: str
    kuma_2fa_token: Optional[str]
    checksum_group_id: Optional[int]
    http_group_id: Optional[int]
    push_interval: int
    http_interval: int
    http_retries: int
    request_timeout: int
    wp_timeout: int
    workers: int
    enable_core_redownload: bool
    quarantine_should_not_exist: bool
    allow_take_ownership: bool
    allow_delete_managed_duplicates: bool
    allow_delete_ignored_managed: bool
    dry_run: bool


def load_config(args: argparse.Namespace) -> Config:
    wpcli_env = os.environ.get("WPCHECK_WPCLI")
    if wpcli_env is not None and wpcli_env.strip() != "":
        wpcli = wpcli_env.strip()
    else:
        candidates: List[str] = []
        which_wp = shutil.which("wp")
        if which_wp:
            candidates.append(which_wp)
        candidates.extend(["/usr/local/bin/wp", "/usr/bin/wp", "/bin/wp", "wp"])
        wpcli = candidates[0]
        for c in candidates:
            if c == "wp":
                if shutil.which("wp"):
                    wpcli = "wp"
                    break
                continue
            if os.path.isfile(c) and os.access(c, os.X_OK):
                wpcli = c
                break
    home_dir = os.environ.get("WPCHECK_HOME_DIR", "/home")
    cache_file = os.environ.get("WPCHECK_CACHE_FILE", "/wpcheck/kuma_cache.json")
    ignore_file = os.environ.get("WPCHECK_IGNORE_FILE", "/wpcheck/wp_checksum_ignore.txt")
    quarantine_dir = os.environ.get("WPCHECK_QUARANTINE_DIR", "/wpcheck/quarantine")

    kuma_url = os.environ.get("WPCHECK_KUMA_URL", "").strip().rstrip("/")
    kuma_user = os.environ.get("WPCHECK_KUMA_USER", "").strip()
    kuma_pass = os.environ.get("WPCHECK_KUMA_PASS", "")
    kuma_2fa_token = os.environ.get("WPCHECK_KUMA_2FA_TOKEN")
    if kuma_2fa_token is not None:
        kuma_2fa_token = kuma_2fa_token.strip() or None

    checksum_group_id = _env_optional_int("WPCHECK_CHECKSUM_GROUP_ID")
    http_group_id = _env_optional_int("WPCHECK_HTTP_GROUP_ID")

    push_interval = _env_int("WPCHECK_PUSH_INTERVAL", 3600)
    http_interval = _env_int("WPCHECK_HTTP_INTERVAL", 60)
    http_retries = _env_int("WPCHECK_HTTP_RETRIES", 5)
    request_timeout = _env_int("WPCHECK_REQUEST_TIMEOUT", 15)
    wp_timeout = _env_int("WPCHECK_WP_TIMEOUT", 120)

    workers = args.workers if args.workers is not None else _env_int("WPCHECK_WORKERS", 8)
    if workers < 1:
        workers = 1

    dry_run = bool(args.dry_run) or _env_bool("WPCHECK_DRY_RUN", False)
    enable_core_redownload = _env_bool("WPCHECK_ENABLE_CORE_REDOWNLOAD", False)
    quarantine_should_not_exist = _env_bool("WPCHECK_QUARANTINE_SHOULD_NOT_EXIST", True)
    allow_take_ownership = _env_bool("WPCHECK_TAKE_OWNERSHIP", False)
    allow_delete_managed_duplicates = _env_bool("WPCHECK_DELETE_MANAGED_DUPLICATES", True)
    allow_delete_ignored_managed = bool(args.cleanup_ignored) or _env_bool("WPCHECK_CLEANUP_IGNORED", False)

    return Config(
        wpcli=wpcli,
        home_dir=home_dir,
        cache_file=cache_file,
        ignore_file=ignore_file,
        quarantine_dir=quarantine_dir,
        kuma_url=kuma_url,
        kuma_user=kuma_user,
        kuma_pass=kuma_pass,
        kuma_2fa_token=kuma_2fa_token,
        checksum_group_id=checksum_group_id,
        http_group_id=http_group_id,
        push_interval=push_interval,
        http_interval=http_interval,
        http_retries=http_retries,
        request_timeout=request_timeout,
        wp_timeout=wp_timeout,
        workers=workers,
        enable_core_redownload=enable_core_redownload,
        quarantine_should_not_exist=quarantine_should_not_exist,
        allow_take_ownership=allow_take_ownership,
        allow_delete_managed_duplicates=allow_delete_managed_duplicates,
        allow_delete_ignored_managed=allow_delete_ignored_managed,
        dry_run=dry_run,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(action: str, result: str = "ok", domain: Optional[str] = None, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "ts": _now_iso(),
        "action": action,
        "result": result,
    }
    if domain is not None:
        payload["domain"] = domain
    payload.update(fields)
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True), flush=True)


def retry(
    func,
    *,
    retries: int,
    base_delay: float,
    max_delay: float,
    action: str,
    domain: Optional[str] = None,
):
    last_exc: Optional[BaseException] = None
    delay = base_delay
    for attempt in range(1, retries + 1):
        try:
            return func()
        except Exception as e:
            last_exc = e
            log_event(action, result="error", domain=domain, attempt=attempt, error=str(e))
            if attempt >= retries:
                break
            time.sleep(delay)
            delay = min(max_delay, delay * 2)
    assert last_exc is not None
    raise last_exc


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_ignore_list(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    entries: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            v = line.strip().lower()
            if v:
                entries.append(v)
    return entries


def read_cache(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        bad_path = f"{path}.corrupt.{ts}"
        try:
            shutil.move(path, bad_path)
        except Exception:
            pass
        log_event("cache_read", result="error", error="cache_corrupt", path=path, moved_to=bad_path)
        return {}


def write_cache_atomic(path: str, data: Dict[str, Any]) -> None:
    safe_mkdir(os.path.dirname(path) or ".")
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def run_wp(wpcli: str, path: str, args: List[str], timeout_s: int) -> Tuple[str, str, int]:
    r = subprocess.run(
        [wpcli] + args,
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
    )
    return r.stdout, r.stderr, r.returncode


def parse_site_domain(siteurl: str) -> Optional[str]:
    siteurl = siteurl.strip()
    if not siteurl:
        return None
    if not siteurl.startswith("http://") and not siteurl.startswith("https://"):
        siteurl = "https://" + siteurl
    p = urlparse(siteurl)
    host = (p.hostname or "").strip().lower()
    if not host:
        return None
    return host


def checksum_failed(stdout: str, stderr: str, returncode: int) -> bool:
    if returncode != 0:
        return True
    for line in (stdout + "\n" + stderr).splitlines():
        if line.strip().startswith("Warning:"):
            return True
    return False


def extract_should_not_exist_files(stdout: str, stderr: str) -> List[str]:
    paths: List[str] = []
    for line in (stdout + "\n" + stderr).splitlines():
        if "should not exist:" not in line:
            continue
        _, _, tail = line.partition("should not exist:")
        p = tail.strip()
        if p:
            paths.append(p)
    return paths


def quarantine_file(site_root: str, quarantine_root: str, domain: str, rel_path: str, dry_run: bool) -> Optional[str]:
    rel_path = rel_path.lstrip("/\\")
    src = os.path.normpath(os.path.join(site_root, rel_path))
    site_root_norm = os.path.normpath(site_root)
    if not src.startswith(site_root_norm + os.sep) and src != site_root_norm:
        raise ValueError(f"unsafe_path:{rel_path}")
    if not os.path.exists(src):
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    dst = os.path.join(quarantine_root, domain, ts, rel_path)
    safe_mkdir(os.path.dirname(dst))
    if dry_run:
        return dst
    shutil.move(src, dst)
    return dst


def find_wp_sites(base: str) -> List[str]:
    hits: List[str] = []
    for root, _, files in os.walk(base):
        if "wp-config.php" in files:
            hits.append(root)
    return hits


class KumaClient:
    def __init__(self, config: Config):
        self._cfg = config
        self._session = requests.Session()
        self._sio = socketio.Client(
            logger=False,
            engineio_logger=False,
            reconnection=True,
            request_timeout=float(config.request_timeout),
            http_session=self._session,
        )
        self._monitor_list: Dict[str, Any] = {}
        self._info: Dict[str, Any] = {}
        self._connected = False
        self._sio.on("monitorList", self._on_monitor_list)
        self._sio.on("info", self._on_info)

    def _on_monitor_list(self, data: Any) -> None:
        if isinstance(data, dict):
            self._monitor_list = data

    def _on_info(self, data: Any) -> None:
        if isinstance(data, dict):
            self._info = data

    def connect_and_login(self) -> None:
        if not self._cfg.kuma_url:
            raise ValueError("missing_kuma_url")
        self._sio.connect(self._cfg.kuma_url, transports=["websocket", "polling"], wait_timeout=self._cfg.request_timeout)
        self._connected = True

        login_data: Dict[str, Any] = {
            "username": self._cfg.kuma_user,
            "password": self._cfg.kuma_pass,
        }
        if self._cfg.kuma_2fa_token:
            login_data["token"] = self._cfg.kuma_2fa_token

        res = self._sio.call("login", login_data, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_login_failed:{res}")

        end = time.time() + float(self._cfg.request_timeout)
        while time.time() < end:
            if self._monitor_list:
                break
            time.sleep(0.25)
        if not self._monitor_list:
            raise RuntimeError("kuma_monitor_list_not_received")

    def disconnect(self) -> None:
        try:
            if self._connected:
                self._sio.disconnect()
        finally:
            self._connected = False

    def list_monitors(self) -> List[Dict[str, Any]]:
        monitors: List[Dict[str, Any]] = []
        for mid, mon in self._monitor_list.items():
            if isinstance(mon, dict):
                m = dict(mon)
                m.setdefault("id", int(mid) if str(mid).isdigit() else mid)
                monitors.append(m)
        return monitors

    def get_monitor(self, monitor_id: int) -> Dict[str, Any]:
        res = self._sio.call("getMonitor", {"monitorID": monitor_id}, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_get_monitor_failed:{res}")
        monitor = res.get("monitor")
        if not isinstance(monitor, dict):
            raise RuntimeError("kuma_get_monitor_missing_monitor")
        return monitor

    def add_monitor(self, monitor: Dict[str, Any]) -> int:
        res = self._sio.call("add", {"monitor": monitor}, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_add_monitor_failed:{res}")
        mid = res.get("monitorID")
        if mid is None:
            mid = res.get("monitorId")
        if mid is None:
            raise RuntimeError(f"kuma_add_monitor_missing_id:{res}")
        return int(mid)

    def edit_monitor(self, monitor: Dict[str, Any]) -> int:
        res = self._sio.call("editMonitor", {"monitor": monitor}, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_edit_monitor_failed:{res}")
        mid = res.get("monitorID")
        if mid is None:
            mid = res.get("monitorId")
        if mid is None:
            raise RuntimeError(f"kuma_edit_monitor_missing_id:{res}")
        return int(mid)

    def delete_monitor(self, monitor_id: int) -> None:
        res = self._sio.call("deleteMonitor", {"monitorID": monitor_id}, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_delete_monitor_failed:{res}")


def send_push(kuma_url: str, token: str, *, status: str, msg: str, timeout_s: int) -> None:
    url = f"{kuma_url}/api/push/{token}"
    params = {"status": status, "msg": msg}
    r = requests.get(url, params=params, timeout=timeout_s)
    if r.status_code != 200:
        raise RuntimeError(f"push_http_{r.status_code}")
    data = r.json()
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError(f"push_failed:{data}")


def monitor_managed_by_wpcheck(monitor: Dict[str, Any]) -> bool:
    desc = str(monitor.get("description") or "")
    return "managed_by=wpcheck" in desc


def build_description(site_path: str, domain: str, kind: str) -> str:
    return f"managed_by=wpcheck;domain={domain};kind={kind};wp_path={site_path}"


def ensure_group_exists(kuma: KumaClient, group_id: Optional[int]) -> Optional[int]:
    if group_id is None:
        return None
    try:
        mon = kuma.get_monitor(int(group_id))
        if not isinstance(mon, dict):
            return None
        return int(group_id)
    except Exception:
        return None


def select_monitor_candidates(monitors: List[Dict[str, Any]], *, name: str) -> List[Dict[str, Any]]:
    return [m for m in monitors if str(m.get("name") or "") == name]


def ensure_domain_monitors(
    kuma: KumaClient,
    cfg: Config,
    *,
    domain: str,
    site_path: str,
) -> Tuple[int, int, str]:
    monitors = kuma.list_monitors()

    http_name = f"WP | {domain} | HTTP"
    checksum_name = f"WP | {domain} | CHECKSUM"

    http_candidates = select_monitor_candidates(monitors, name=http_name)
    checksum_candidates = select_monitor_candidates(monitors, name=checksum_name)

    http_mon = None
    checksum_mon = None

    managed_http = [m for m in http_candidates if monitor_managed_by_wpcheck(m)]
    managed_checksum = [m for m in checksum_candidates if monitor_managed_by_wpcheck(m)]

    if managed_http:
        http_mon = managed_http[0]
        if len(managed_http) > 1 and cfg.allow_delete_managed_duplicates and not cfg.dry_run:
            for dup in managed_http[1:]:
                kuma.delete_monitor(int(dup["id"]))
                log_event("kuma_delete_duplicate", domain=domain, monitor_id=int(dup["id"]), name=http_name)
    elif http_candidates:
        http_mon = http_candidates[0]

    if managed_checksum:
        checksum_mon = managed_checksum[0]
        if len(managed_checksum) > 1 and cfg.allow_delete_managed_duplicates and not cfg.dry_run:
            for dup in managed_checksum[1:]:
                kuma.delete_monitor(int(dup["id"]))
                log_event("kuma_delete_duplicate", domain=domain, monitor_id=int(dup["id"]), name=checksum_name)
    elif checksum_candidates:
        checksum_mon = checksum_candidates[0]

    http_parent = ensure_group_exists(kuma, cfg.http_group_id)
    checksum_parent = ensure_group_exists(kuma, cfg.checksum_group_id)

    if http_mon is None:
        monitor_obj: Dict[str, Any] = {
            "type": "http",
            "name": http_name,
            "url": f"https://{domain}",
            "interval": cfg.http_interval,
            "retryInterval": cfg.http_interval,
            "maxretries": cfg.http_retries,
            "description": build_description(site_path, domain, "http"),
        }
        if http_parent is not None:
            monitor_obj["parent"] = http_parent
        if cfg.dry_run:
            http_id = -1
        else:
            http_id = kuma.add_monitor(monitor_obj)
        log_event("kuma_http_monitor_create", domain=domain, monitor_id=http_id, name=http_name, dry_run=cfg.dry_run)
    else:
        http_id = int(http_mon["id"])
        if cfg.allow_take_ownership and not monitor_managed_by_wpcheck(http_mon):
            full = kuma.get_monitor(http_id)
            full["description"] = build_description(site_path, domain, "http")
            if http_parent is not None:
                full["parent"] = http_parent
            full["name"] = http_name
            full["url"] = f"https://{domain}"
            if cfg.dry_run:
                log_event("kuma_http_monitor_take_ownership", domain=domain, monitor_id=http_id, dry_run=True)
            else:
                kuma.edit_monitor(full)
                log_event("kuma_http_monitor_take_ownership", domain=domain, monitor_id=http_id)

    if checksum_mon is None:
        monitor_obj = {
            "type": "push",
            "name": checksum_name,
            "interval": cfg.push_interval,
            "description": build_description(site_path, domain, "checksum"),
        }
        if checksum_parent is not None:
            monitor_obj["parent"] = checksum_parent
        if cfg.dry_run:
            checksum_id = -1
            push_token = ""
        else:
            checksum_id = kuma.add_monitor(monitor_obj)
            full = retry(
                lambda: kuma.get_monitor(checksum_id),
                retries=5,
                base_delay=0.5,
                max_delay=5,
                action="kuma_get_push_token",
                domain=domain,
            )
            push_token = str(full.get("pushToken") or "")
            if not push_token:
                raise RuntimeError("kuma_push_token_missing")
        log_event("kuma_checksum_monitor_create", domain=domain, monitor_id=checksum_id, name=checksum_name, dry_run=cfg.dry_run)
    else:
        checksum_id = int(checksum_mon["id"])
        if cfg.dry_run:
            push_token = ""
        else:
            full = kuma.get_monitor(checksum_id)
            push_token = str(full.get("pushToken") or "")
            if not push_token:
                raise RuntimeError("kuma_push_token_missing")

        if cfg.allow_take_ownership and not monitor_managed_by_wpcheck(checksum_mon):
            full = kuma.get_monitor(checksum_id)
            full["description"] = build_description(site_path, domain, "checksum")
            if checksum_parent is not None:
                full["parent"] = checksum_parent
            full["name"] = checksum_name
            if cfg.dry_run:
                log_event("kuma_checksum_monitor_take_ownership", domain=domain, monitor_id=checksum_id, dry_run=True)
            else:
                kuma.edit_monitor(full)
                log_event("kuma_checksum_monitor_take_ownership", domain=domain, monitor_id=checksum_id)

    return http_id, checksum_id, push_token


def preflight(cfg: Config) -> None:
    if os.path.sep in cfg.wpcli:
        if not os.path.isfile(cfg.wpcli) or not os.access(cfg.wpcli, os.X_OK):
            raise RuntimeError(f"wpcli_not_executable:{cfg.wpcli}")
    else:
        if shutil.which(cfg.wpcli) is None:
            raise RuntimeError(f"wpcli_not_found_in_path:{cfg.wpcli}")
    if not os.path.isdir(cfg.home_dir):
        raise RuntimeError(f"home_dir_missing:{cfg.home_dir}")
    safe_mkdir(os.path.dirname(cfg.cache_file) or ".")
    safe_mkdir(cfg.quarantine_dir)
    if not cfg.kuma_url:
        raise RuntimeError("missing_env:WPCHECK_KUMA_URL")
    if not cfg.kuma_user:
        raise RuntimeError("missing_env:WPCHECK_KUMA_USER")
    if cfg.kuma_pass == "":
        raise RuntimeError("missing_env:WPCHECK_KUMA_PASS")

    try:
        r = requests.get(f"{cfg.kuma_url}/api/entry-page", timeout=cfg.request_timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"kuma_unreachable_http_{r.status_code}")
    except requests.RequestException as e:
        raise RuntimeError(f"kuma_unreachable:{e}")

    try:
        socket.gethostbyname(urlparse(cfg.kuma_url).hostname or "")
    except Exception:
        pass


@dataclass
class SiteWork:
    site_path: str


@dataclass
class SiteResult:
    site_path: str
    domain: Optional[str]
    ignored: bool
    checksum_failed: bool
    quarantined: List[Tuple[str, Optional[str]]]
    error: Optional[str]


def process_site(cfg: Config, site_path: str, ignored_set: set) -> SiteResult:
    quarantined: List[Tuple[str, Optional[str]]] = []
    try:
        out, err, rc = run_wp(
            cfg.wpcli,
            site_path,
            ["option", "get", "siteurl", "--allow-root", "--skip-plugins", "--skip-themes", "--quiet"],
            cfg.wp_timeout,
        )
        domain = parse_site_domain(out)
        if not domain:
            return SiteResult(site_path=site_path, domain=None, ignored=False, checksum_failed=True, quarantined=[], error="missing_domain")
        if domain in ignored_set:
            return SiteResult(site_path=site_path, domain=domain, ignored=True, checksum_failed=False, quarantined=[], error=None)

        out, err, rc = run_wp(
            cfg.wpcli,
            site_path,
            ["core", "verify-checksums", "--allow-root", "--skip-plugins", "--skip-themes"],
            cfg.wp_timeout,
        )
        failed = checksum_failed(out, err, rc)

        if failed and cfg.enable_core_redownload:
            run_wp(
                cfg.wpcli,
                site_path,
                ["core", "download", "--force", "--skip-content", "--allow-root"],
                cfg.wp_timeout,
            )
            out, err, rc = run_wp(
                cfg.wpcli,
                site_path,
                ["core", "verify-checksums", "--allow-root", "--skip-plugins", "--skip-themes"],
                cfg.wp_timeout,
            )
            failed = checksum_failed(out, err, rc)

        if failed and cfg.quarantine_should_not_exist:
            suspicious = extract_should_not_exist_files(out, err)
            for rel_path in suspicious:
                try:
                    dst = quarantine_file(site_path, cfg.quarantine_dir, domain, rel_path, cfg.dry_run)
                    quarantined.append((rel_path, dst))
                except Exception as e:
                    quarantined.append((rel_path, None))
                    log_event("quarantine_failed", result="error", domain=domain, site_path=site_path, rel_path=rel_path, error=str(e))

            if suspicious and not cfg.dry_run:
                out, err, rc = run_wp(
                    cfg.wpcli,
                    site_path,
                    ["core", "verify-checksums", "--allow-root", "--skip-plugins", "--skip-themes"],
                    cfg.wp_timeout,
                )
                failed = checksum_failed(out, err, rc)

        return SiteResult(site_path=site_path, domain=domain, ignored=False, checksum_failed=failed, quarantined=quarantined, error=None)
    except subprocess.TimeoutExpired:
        return SiteResult(site_path=site_path, domain=None, ignored=False, checksum_failed=True, quarantined=quarantined, error="wp_timeout")
    except Exception as e:
        return SiteResult(site_path=site_path, domain=None, ignored=False, checksum_failed=True, quarantined=quarantined, error=str(e))


# ---------------- ARGPARSE ----------------
parser = argparse.ArgumentParser()
parser.add_argument("--limit", type=int, default=0, help="Limit number of sites to scan (0 = all)")
parser.add_argument("--cleanup-only", action="store_true", help="Only cleanup ignored sites (managed monitors only)")
parser.add_argument("--cleanup-ignored", action="store_true", help="Delete managed monitors for ignored domains")
parser.add_argument("--workers", type=int, default=None, help="Number of concurrent WP workers")
parser.add_argument("--dry-run", action="store_true", help="Do not modify Kuma or filesystem")
args = parser.parse_args()


def main() -> int:
    cfg = load_config(args)
    preflight(cfg)

    cache = read_cache(cfg.cache_file)
    ignored_list = read_ignore_list(cfg.ignore_file)
    ignored_set = set(ignored_list)

    kuma = KumaClient(cfg)
    try:
        retry(
            kuma.connect_and_login,
            retries=3,
            base_delay=1,
            max_delay=10,
            action="kuma_connect_login",
        )
        log_event("kuma_login", version=kuma._info.get("version"))

        if args.cleanup_only:
            if not cfg.allow_delete_ignored_managed:
                log_event("cleanup_skipped", result="error", error="cleanup_requires_flag", hint="use --cleanup-ignored")
                return 2

            monitors = kuma.list_monitors()
            for mon in monitors:
                name = str(mon.get("name") or "")
                if not name.startswith("WP | "):
                    continue
                desc = str(mon.get("description") or "")
                domain = None
                if "domain=" in desc:
                    _, _, tail = desc.partition("domain=")
                    domain = tail.split(";", 1)[0].strip().lower() or None
                if not domain or domain not in ignored_set:
                    continue
                if not monitor_managed_by_wpcheck(mon):
                    log_event("cleanup_skip_unmanaged", domain=domain, monitor_id=mon.get("id"), name=name)
                    continue
                if cfg.dry_run:
                    log_event("cleanup_delete", domain=domain, monitor_id=mon.get("id"), name=name, dry_run=True)
                    continue
                kuma.delete_monitor(int(mon["id"]))
                log_event("cleanup_delete", domain=domain, monitor_id=int(mon["id"]), name=name)
            return 0

        sites: List[str] = []
        for user in os.listdir(cfg.home_dir):
            base = os.path.join(cfg.home_dir, user, "public_html")
            if not os.path.isdir(base):
                continue
            sites.extend(find_wp_sites(base))
        if args.limit and args.limit > 0:
            sites = sites[: args.limit]

        log_event("scan_start", sites=len(sites), workers=cfg.workers)
        failed_sites: Dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
            futures = {ex.submit(process_site, cfg, site, ignored_set): site for site in sites}
            for fut in as_completed(futures):
                res = fut.result()
                if res.domain:
                    log_event(
                        "site_processed",
                        domain=res.domain,
                        site_path=res.site_path,
                        ignored=res.ignored,
                        checksum_failed=res.checksum_failed,
                        quarantined=len(res.quarantined),
                        error=res.error,
                    )
                else:
                    log_event(
                        "site_processed",
                        result="error",
                        site_path=res.site_path,
                        error=res.error or "unknown",
                    )
                if res.ignored or not res.domain:
                    continue

                domain = res.domain
                def _ensure():
                    return ensure_domain_monitors(kuma, cfg, domain=domain, site_path=res.site_path)

                http_id, checksum_id, push_token = retry(
                    _ensure,
                    retries=3,
                    base_delay=1,
                    max_delay=10,
                    action="kuma_reconcile",
                    domain=domain,
                )
                cache.setdefault(domain, {})
                cache[domain].update(
                    {
                        "site_path": res.site_path,
                        "http_monitor_id": http_id,
                        "checksum_monitor_id": checksum_id,
                        "checksum_token": push_token,
                        "last_seen": _now_iso(),
                    }
                )
                try:
                    write_cache_atomic(cfg.cache_file, cache)
                except Exception as e:
                    log_event("cache_write", result="error", domain=domain, error=str(e), path=cfg.cache_file)

                if cfg.dry_run:
                    continue

                status = "down" if res.checksum_failed else "up"
                msg = "checksum_failed" if res.checksum_failed else "ok"
                retry(
                    lambda: send_push(cfg.kuma_url, push_token, status=status, msg=msg, timeout_s=cfg.request_timeout),
                    retries=3,
                    base_delay=1,
                    max_delay=10,
                    action="kuma_push",
                    domain=domain,
                )
                if res.checksum_failed:
                    failed_sites[domain] = res.site_path

        log_event("scan_complete", failed=len(failed_sites))
        for d, p in sorted(failed_sites.items()):
            log_event("checksum_failure", result="error", domain=d, site_path=p)
        return 1 if failed_sites else 0
    finally:
        kuma.disconnect()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log_event("fatal", result="error", error=str(e))
        sys.exit(2)
