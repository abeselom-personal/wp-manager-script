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
import secrets
import hashlib
import threading
from collections import Counter
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


def normalize_base_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.scheme or not p.netloc:
        return (raw or "").rstrip("/")
    return f"{p.scheme}://{p.netloc}".rstrip("/")


def websocket_client_available() -> bool:
    try:
        import websocket  # type: ignore

        return True
    except Exception:
        return False


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
    kuma_verify_ssl: bool
    checksum_group_id: Optional[int]
    http_group_id: Optional[int]
    push_interval: int
    http_interval: int
    http_retries: int
    request_timeout: int
    monitor_list_timeout: int
    wp_timeout: int
    workers: int
    enable_core_redownload: bool
    quarantine_should_not_exist: bool
    allow_take_ownership: bool
    allow_delete_managed_duplicates: bool
    allow_delete_ignored_managed: bool
    dry_run: bool
    missing_domain_push_token: str
    missing_domain_alert_threshold: int


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

    kuma_url = normalize_base_url(os.environ.get("WPCHECK_KUMA_URL", ""))
    kuma_user = os.environ.get("WPCHECK_KUMA_USER", "").strip()
    kuma_pass = os.environ.get("WPCHECK_KUMA_PASS", "")
    kuma_2fa_token = os.environ.get("WPCHECK_KUMA_2FA_TOKEN")
    if kuma_2fa_token is not None:
        kuma_2fa_token = kuma_2fa_token.strip() or None

    kuma_verify_ssl = _env_bool("WPCHECK_KUMA_VERIFY_SSL", True)

    checksum_group_id = _env_optional_int("WPCHECK_CHECKSUM_GROUP_ID")
    http_group_id = _env_optional_int("WPCHECK_HTTP_GROUP_ID")

    push_interval = _env_int("WPCHECK_PUSH_INTERVAL", 3600)
    http_interval = _env_int("WPCHECK_HTTP_INTERVAL", 60)
    http_retries = _env_int("WPCHECK_HTTP_RETRIES", 5)
    request_timeout = _env_int("WPCHECK_REQUEST_TIMEOUT", 15)
    monitor_list_timeout = _env_int("WPCHECK_MONITOR_LIST_TIMEOUT", 60)
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

    missing_domain_push_token = str(os.environ.get("WPCHECK_MISSING_DOMAIN_PUSH_TOKEN", "") or "").strip()
    missing_domain_alert_threshold = _env_int("WPCHECK_MISSING_DOMAIN_ALERT_THRESHOLD", 0)

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
        kuma_verify_ssl=kuma_verify_ssl,
        checksum_group_id=checksum_group_id,
        http_group_id=http_group_id,
        push_interval=push_interval,
        http_interval=http_interval,
        http_retries=http_retries,
        request_timeout=request_timeout,
        monitor_list_timeout=monitor_list_timeout,
        wp_timeout=wp_timeout,
        workers=workers,
        enable_core_redownload=enable_core_redownload,
        quarantine_should_not_exist=quarantine_should_not_exist,
        allow_take_ownership=allow_take_ownership,
        allow_delete_managed_duplicates=allow_delete_managed_duplicates,
        allow_delete_ignored_managed=allow_delete_ignored_managed,
        dry_run=dry_run,
        missing_domain_push_token=missing_domain_push_token,
        missing_domain_alert_threshold=missing_domain_alert_threshold,
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


@dataclass
class RunSummary:
    mode: str
    dry_run: bool
    removed_monitors: List[Dict[str, Any]]
    created_monitors: List[Dict[str, Any]]
    cache_purges: List[Dict[str, Any]]
    quarantined_files: List[Dict[str, Any]]
    counts: Dict[str, int]
    errors: Counter
    _lock: threading.Lock

    @staticmethod
    def new(*, mode: str, dry_run: bool) -> "RunSummary":
        return RunSummary(
            mode=mode,
            dry_run=dry_run,
            removed_monitors=[],
            created_monitors=[],
            cache_purges=[],
            quarantined_files=[],
            counts={},
            errors=Counter(),
            _lock=threading.Lock(),
        )

    def inc(self, key: str, by: int = 1) -> None:
        with self._lock:
            self.counts[key] = int(self.counts.get(key, 0)) + int(by)

    def add_removed_monitor(self, **row: Any) -> None:
        with self._lock:
            self.removed_monitors.append(dict(row))
            self.counts["removed_monitors"] = int(self.counts.get("removed_monitors", 0)) + 1

    def add_created_monitor(self, **row: Any) -> None:
        with self._lock:
            self.created_monitors.append(dict(row))
            self.counts["created_monitors"] = int(self.counts.get("created_monitors", 0)) + 1

    def add_cache_purge(self, **row: Any) -> None:
        with self._lock:
            self.cache_purges.append(dict(row))
            self.counts["cache_purges"] = int(self.counts.get("cache_purges", 0)) + 1

    def add_quarantine(self, **row: Any) -> None:
        with self._lock:
            self.quarantined_files.append(dict(row))
            self.counts["quarantined_files"] = int(self.counts.get("quarantined_files", 0)) + 1

    def add_error(self, err: str) -> None:
        with self._lock:
            self.errors[str(err or "unknown")] += 1


RUN_SUMMARY: Optional[RunSummary] = None


def _summary() -> Optional[RunSummary]:
    return RUN_SUMMARY


def _fmt_table(headers: List[str], rows: List[List[str]]) -> str:
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]))

    def _row(items: List[str]) -> str:
        return " | ".join(items[i].ljust(widths[i]) for i in range(cols))

    sep = "-+-".join("-" * w for w in widths)
    out = [_row(headers), sep]
    out.extend(_row(r) for r in rows)
    return "\n".join(out)


def print_run_summary(cfg: Config, summary: RunSummary) -> None:
    max_items = 250

    def _clip(items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        if len(items) <= max_items:
            return items, 0
        return items[:max_items], len(items) - max_items

    removed, removed_more = _clip(summary.removed_monitors)
    created, created_more = _clip(summary.created_monitors)
    purges, purges_more = _clip(summary.cache_purges)
    quarantined, quarantined_more = _clip(summary.quarantined_files)

    print("\n" + "=" * 72)
    print("WPCHECK SUMMARY")
    print("=" * 72)
    print(f"Mode      : {summary.mode}")
    print(f"Dry run   : {summary.dry_run}")
    print(f"Kuma URL  : {cfg.kuma_url}")

    if summary.counts:
        count_rows = [[k, str(v)] for k, v in sorted(summary.counts.items(), key=lambda kv: kv[0])]
        print("\nCOUNTS")
        print(_fmt_table(["key", "value"], count_rows))

    if summary.errors:
        err_rows = [[k, str(v)] for k, v in sorted(summary.errors.items(), key=lambda kv: (-kv[1], kv[0]))]
        print("\nERRORS")
        print(_fmt_table(["error", "count"], err_rows))

    if removed:
        rows: List[List[str]] = []
        for r in removed:
            rows.append(
                [
                    str(r.get("source") or ""),
                    str(r.get("domain") or ""),
                    str(r.get("monitor_id") or ""),
                    str(r.get("name") or ""),
                    "DRY" if r.get("dry_run") else "",
                ]
            )
        print("\nREMOVED MONITORS")
        print(_fmt_table(["source", "domain", "id", "name", ""], rows))
        if removed_more:
            print(f"... and {removed_more} more removed monitor records")
    else:
        print("\nREMOVED MONITORS")
        print("(none)")

    if purges:
        rows = []
        for p in purges:
            rows.append([str(p.get("source") or ""), str(p.get("domain") or ""), str(p.get("site_path") or ""), "DRY" if p.get("dry_run") else ""])
        print("\nCACHE PURGES")
        print(_fmt_table(["source", "domain", "site_path", ""], rows))
        if purges_more:
            print(f"... and {purges_more} more cache purge records")
    else:
        print("\nCACHE PURGES")
        print("(none)")

    if quarantined:
        rows = []
        for q in quarantined:
            rows.append(
                [
                    str(q.get("domain") or ""),
                    str(q.get("site_path") or ""),
                    str(q.get("rel_path") or ""),
                    str(q.get("dst") or ""),
                    "DRY" if q.get("dry_run") else "",
                ]
            )
        print("\nQUARANTINED FILES")
        print(_fmt_table(["domain", "site_path", "rel_path", "dst", ""], rows))
        if quarantined_more:
            print(f"... and {quarantined_more} more quarantined file records")
    else:
        print("\nQUARANTINED FILES")
        print("(none)")

    if created:
        rows = []
        for c in created:
            rows.append([str(c.get("kind") or ""), str(c.get("domain") or ""), str(c.get("monitor_id") or ""), str(c.get("name") or ""), "DRY" if c.get("dry_run") else ""])
        print("\nCREATED MONITORS")
        print(_fmt_table(["kind", "domain", "id", "name", ""], rows))
        if created_more:
            print(f"... and {created_more} more created monitor records")
    else:
        print("\nCREATED MONITORS")
        print("(none)")

    print("=" * 72 + "\n")


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
            log_event(
                action,
                result="error",
                domain=domain,
                attempt=attempt,
                error=str(e),
                error_type=type(e).__name__,
                error_repr=repr(e),
            )
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
            v = line.strip()
            if not v or v.startswith("#"):
                continue
            norm = normalize_domain_value(v)
            if norm:
                entries.append(norm)
    return entries


def normalize_domain_value(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw.startswith("#"):
        return None

    candidate = raw
    if "://" not in candidate and "/" in candidate:
        candidate = "https://" + candidate

    if "://" in candidate:
        host = (urlparse(candidate).hostname or "").strip().lower()
        return host or None

    return raw.strip().lower()


def build_ignored_set(ignored_list: List[str]) -> set:
    out: set = set()
    for d in ignored_list:
        d = (d or "").strip().lower()
        if not d:
            continue
        out.add(d)
        if d.startswith("www."):
            out.add(d[4:])
        else:
            out.add("www." + d)
    return out


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
    if dry_run:
        return dst
    safe_mkdir(os.path.dirname(dst))
    if os.path.exists(dst):
        base = dst
        i = 1
        while os.path.exists(dst):
            dst = f"{base}.{i}"
            i += 1
    shutil.move(src, dst)
    if os.path.exists(src):
        raise RuntimeError("quarantine_source_still_exists")
    return dst


def find_wp_sites(base: str) -> List[str]:
    hits: List[str] = []
    for root, _, files in os.walk(base):
        if "wp-config.php" in files:
            if f"{os.sep}wp-content{os.sep}" in root:
                continue
            if not (
                os.path.isdir(os.path.join(root, "wp-includes"))
                or os.path.isdir(os.path.join(root, "wp-admin"))
            ):
                continue
            hits.append(root)
    return hits


class KumaClient:
    def __init__(self, config: Config):
        self._cfg = config
        self._session = requests.Session()
        self._session.verify = bool(config.kuma_verify_ssl)
        self._sio = socketio.Client(
            logger=False,
            engineio_logger=False,
            reconnection=True,
            request_timeout=float(config.request_timeout),
            http_session=self._session,
            ssl_verify=bool(config.kuma_verify_ssl),
        )
        self._monitor_list: Dict[str, Any] = {}
        self._monitor_list_received = False
        self._info: Dict[str, Any] = {}
        self._connected = False
        self._sio.on("monitorList", self._on_monitor_list)
        self._sio.on("info", self._on_info)

    def _on_monitor_list(self, data: Any) -> None:
        self._monitor_list_received = True
        if isinstance(data, dict):
            if "monitorList" in data and isinstance(data.get("monitorList"), dict):
                self._monitor_list = data["monitorList"]
            else:
                self._monitor_list = data
        elif isinstance(data, list):
            rebuilt: Dict[str, Any] = {}
            for item in data:
                if not isinstance(item, dict):
                    continue
                mid = item.get("id")
                if mid is None:
                    continue
                rebuilt[str(mid)] = item
            self._monitor_list = rebuilt

    def _on_info(self, data: Any) -> None:
        if isinstance(data, dict):
            self._info = data

    def connect_and_login(self) -> None:
        if not self._cfg.kuma_url:
            raise ValueError("missing_kuma_url")

        attempts: List[List[str]]
        if websocket_client_available():
            attempts = [["websocket"], ["polling"]]
        else:
            attempts = [["polling"]]

        last_exc: Optional[BaseException] = None
        for transports in attempts:
            if self._connected:
                self.disconnect()
            self._monitor_list = {}
            self._monitor_list_received = False

            try:
                log_event("kuma_socket_connect", url=self._cfg.kuma_url, transports=transports)
                self._sio.connect(self._cfg.kuma_url, transports=transports, wait_timeout=self._cfg.request_timeout)
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
                log_event("kuma_socket_login_ok", url=self._cfg.kuma_url, transports=transports)

                end = time.time() + float(self._cfg.monitor_list_timeout)
                while time.time() < end:
                    if self._monitor_list_received:
                        break
                    time.sleep(0.25)
                if not self._monitor_list_received:
                    raise RuntimeError("kuma_monitor_list_not_received")
                log_event("kuma_monitor_list_received", count=len(self._monitor_list), transports=transports)
                return
            except Exception as e:
                last_exc = e
                log_event(
                    "kuma_socket_connect_failed",
                    result="error",
                    url=self._cfg.kuma_url,
                    transports=transports,
                    error=str(e),
                    error_type=type(e).__name__,
                    error_repr=repr(e),
                )
                self.disconnect()
                continue

        assert last_exc is not None
        raise last_exc

    def disconnect(self) -> None:
        try:
            if self._connected:
                self._sio.disconnect()
        finally:
            self._connected = False

    def refresh_monitor_list(self) -> None:
        self._monitor_list_received = False
        res = self._sio.call("getMonitorList", timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_get_monitor_list_failed:{res}")

        end = time.time() + float(self._cfg.monitor_list_timeout)
        while time.time() < end:
            if self._monitor_list_received:
                break
            time.sleep(0.25)
        if not self._monitor_list_received:
            raise RuntimeError("kuma_monitor_list_not_received")

    def list_monitors(self) -> List[Dict[str, Any]]:
        monitors: List[Dict[str, Any]] = []
        for mid, mon in self._monitor_list.items():
            if isinstance(mon, dict):
                m = dict(mon)
                m.setdefault("id", int(mid) if str(mid).isdigit() else mid)
                monitors.append(m)
        return monitors

    def get_monitor(self, monitor_id: int) -> Dict[str, Any]:
        res = self._sio.call("getMonitor", monitor_id, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_get_monitor_failed:{res}")
        monitor = res.get("monitor")
        if not isinstance(monitor, dict):
            raise RuntimeError("kuma_get_monitor_missing_monitor")
        return monitor

    def add_monitor(self, monitor: Dict[str, Any]) -> int:
        monitor.setdefault("notificationIDList", [])
        monitor.setdefault("accepted_statuscodes", ["200-299"])
        monitor.setdefault("conditions", [])
        monitor.setdefault("kafkaProducerBrokers", [])
        monitor.setdefault("kafkaProducerSaslOptions", {})
        monitor.setdefault("rabbitmqNodes", [])
        res = self._sio.call("add", monitor, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_add_monitor_failed:{res}")
        mid = res.get("monitorID")
        if mid is None:
            mid = res.get("monitorId")
        if mid is None:
            raise RuntimeError(f"kuma_add_monitor_missing_id:{res}")
        return int(mid)

    def edit_monitor(self, monitor: Dict[str, Any]) -> int:
        monitor.setdefault("notificationIDList", [])
        monitor.setdefault("accepted_statuscodes", ["200-299"])
        monitor.setdefault("conditions", [])
        monitor.setdefault("kafkaProducerBrokers", [])
        monitor.setdefault("kafkaProducerSaslOptions", {})
        monitor.setdefault("rabbitmqNodes", [])
        res = self._sio.call("editMonitor", monitor, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_edit_monitor_failed:{res}")
        mid = res.get("monitorID")
        if mid is None:
            mid = res.get("monitorId")
        if mid is None:
            raise RuntimeError(f"kuma_edit_monitor_missing_id:{res}")
        return int(mid)

    def delete_monitor(self, monitor_id: int) -> None:
        res = self._sio.call("deleteMonitor", monitor_id, timeout=self._cfg.request_timeout)
        if not isinstance(res, dict) or not res.get("ok"):
            raise RuntimeError(f"kuma_delete_monitor_failed:{res}")


def send_push(kuma_url: str, token: str, *, status: str, msg: str, timeout_s: int, verify_ssl: bool) -> None:
    url = f"{kuma_url}/api/push/{token}"
    params = {"status": status, "msg": msg}
    r = requests.get(url, params=params, timeout=timeout_s, verify=bool(verify_ssl))
    if r.status_code != 200:
        raise RuntimeError(f"push_http_{r.status_code}")
    data = r.json()
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError(f"push_failed:{data}")


def monitor_managed_by_wpcheck(monitor: Dict[str, Any]) -> bool:
    desc = str(monitor.get("description") or "")
    return "managed_by=wpcheck" in desc


def parse_description_kv(desc: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (desc or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k:
            out[k] = v
    return out


def delete_wpcheck_monitors_for_domain(kuma: "KumaClient", cfg: Config, domain: str) -> bool:
    domain_l = (domain or "").strip().lower()
    if not domain_l:
        return False

    monitors = kuma.list_monitors()
    domain_aliases = {domain_l}
    if domain_l.startswith("www."):
        domain_aliases.add(domain_l[4:])
    else:
        domain_aliases.add("www." + domain_l)

    expected_names = set()
    for d in domain_aliases:
        expected_names.add(f"WP | {d} | HTTP".lower())
        expected_names.add(f"WP | {d} | CHECKSUM".lower())

    log_event(
        "cleanup_match_plan",
        domain=domain_l,
        domain_aliases=sorted(domain_aliases),
        expected_names=sorted(expected_names),
        monitors_total=len(monitors),
    )

    deleted_any = False
    for mon in monitors:
        if not isinstance(mon, dict):
            continue
        name = str(mon.get("name") or "")
        name_l = name.strip().lower()
        desc_l = str(mon.get("description") or "").lower()

        managed_match = monitor_managed_by_wpcheck(mon) and any(f"domain={d};" in desc_l for d in domain_aliases)
        name_match = name_l in expected_names
        if not (managed_match or name_match):
            continue

        mid = mon.get("id")
        if cfg.dry_run:
            log_event("cleanup_delete", domain=domain_l, monitor_id=mid, name=name, dry_run=True)
            s = _summary()
            if s is not None:
                s.add_removed_monitor(source="cleanup_ignored", domain=domain_l, monitor_id=mid, name=name, dry_run=True)
            deleted_any = True
            continue
        try:
            kuma.delete_monitor(int(mid))
            log_event("cleanup_delete", domain=domain_l, monitor_id=int(mid), name=name)
            s = _summary()
            if s is not None:
                s.add_removed_monitor(source="cleanup_ignored", domain=domain_l, monitor_id=int(mid), name=name, dry_run=False)
            deleted_any = True
        except Exception as e:
            log_event("cleanup_delete", result="error", domain=domain_l, monitor_id=mid, name=name, error=str(e), error_type=type(e).__name__, error_repr=repr(e))

    return deleted_any


def prune_orphan_monitoring_data(kuma: "KumaClient", cfg: Config, cache: Dict[str, Any]) -> None:
    monitors = kuma.list_monitors()
    deleted_any = False

    for mon in monitors:
        if not isinstance(mon, dict):
            continue
        if not monitor_managed_by_wpcheck(mon):
            continue
        desc = str(mon.get("description") or "")
        kv = parse_description_kv(desc)
        wp_path = str(kv.get("wp_path") or "").strip()
        domain = str(kv.get("domain") or "").strip().lower()
        if not wp_path:
            continue
        if os.path.isdir(wp_path):
            continue

        mid = mon.get("id")
        name = str(mon.get("name") or "")
        if cfg.dry_run:
            log_event("prune_orphan_monitor", domain=domain or None, monitor_id=mid, name=name, wp_path=wp_path, dry_run=True)
            s = _summary()
            if s is not None:
                s.add_removed_monitor(source="prune_orphan", domain=domain or None, monitor_id=mid, name=name, dry_run=True, wp_path=wp_path)
            deleted_any = True
            continue
        try:
            kuma.delete_monitor(int(mid))
            log_event("prune_orphan_monitor", domain=domain or None, monitor_id=int(mid), name=name, wp_path=wp_path)
            s = _summary()
            if s is not None:
                s.add_removed_monitor(source="prune_orphan", domain=domain or None, monitor_id=int(mid), name=name, dry_run=False, wp_path=wp_path)
            deleted_any = True
        except Exception as e:
            log_event(
                "prune_orphan_monitor",
                result="error",
                domain=domain or None,
                monitor_id=mid,
                name=name,
                wp_path=wp_path,
                error=str(e),
                error_type=type(e).__name__,
                error_repr=repr(e),
            )

    stale_domains: List[str] = []
    for d, entry in list(cache.items()):
        if not isinstance(entry, dict):
            continue
        site_path = str(entry.get("site_path") or "").strip()
        if not site_path:
            continue
        if os.path.isdir(site_path):
            continue
        stale_domains.append(str(d).strip().lower())
        log_event("prune_orphan_cache_entry", domain=str(d).strip().lower(), site_path=site_path, dry_run=cfg.dry_run)
        s = _summary()
        if s is not None:
            s.add_cache_purge(source="prune_orphan", domain=str(d).strip().lower(), site_path=site_path, dry_run=cfg.dry_run)

    for d in stale_domains:
        deleted_any = delete_wpcheck_monitors_for_domain(kuma, cfg, d) or deleted_any
        if cfg.dry_run:
            continue
        if d in cache:
            del cache[d]

    if stale_domains and not cfg.dry_run:
        try:
            write_cache_atomic(cfg.cache_file, cache)
        except Exception as e:
            log_event("cache_write", result="error", error=str(e), error_type=type(e).__name__, error_repr=repr(e), path=cfg.cache_file)

    if deleted_any:
        try:
            kuma.refresh_monitor_list()
        except Exception:
            pass


def build_description(site_path: str, domain: str, kind: str) -> str:
    return f"managed_by=wpcheck;domain={domain};kind={kind};wp_path={site_path}"


def cleanup_ignored_domain(kuma: "KumaClient", cfg: Config, cache: Dict[str, Any], domain: str) -> None:
    domain_l = (domain or "").strip().lower()
    if not domain_l:
        return

    deleted_any = delete_wpcheck_monitors_for_domain(kuma, cfg, domain_l)

    if domain_l in cache:
        if cfg.dry_run:
            log_event("cleanup_cache_purge", domain=domain_l, dry_run=True)
            s = _summary()
            if s is not None:
                s.add_cache_purge(source="cleanup_ignored", domain=domain_l, site_path=str(cache.get(domain_l, {}).get("site_path") or ""), dry_run=True)
        else:
            del cache[domain_l]
            log_event("cleanup_cache_purge", domain=domain_l)
            s = _summary()
            if s is not None:
                s.add_cache_purge(source="cleanup_ignored", domain=domain_l, site_path="", dry_run=False)
            try:
                write_cache_atomic(cfg.cache_file, cache)
            except Exception as e:
                log_event("cache_write", result="error", domain=domain_l, error=str(e), error_type=type(e).__name__, error_repr=repr(e), path=cfg.cache_file)
    elif deleted_any:
        log_event("cleanup_cache_missing", domain=domain_l)


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
    cached_push_token: Optional[str] = None,
) -> Tuple[int, int, str]:
    try:
        kuma.refresh_monitor_list()
    except Exception:
        pass

    monitors = kuma.list_monitors()

    http_name = f"WP | {domain} | HTTP"
    checksum_name = f"WP | {domain} | CHECKSUM"

    http_candidates = select_monitor_candidates(monitors, name=http_name)
    checksum_candidates = select_monitor_candidates(monitors, name=checksum_name)

    http_mon = None
    checksum_mon = None

    managed_http = [m for m in http_candidates if monitor_managed_by_wpcheck(m)]
    managed_checksum = [m for m in checksum_candidates if monitor_managed_by_wpcheck(m)]

    log_event(
        "kuma_monitor_candidates",
        domain=domain,
        http_name=http_name,
        checksum_name=checksum_name,
        monitors_total=len(monitors),
        http_candidates=len(http_candidates),
        checksum_candidates=len(checksum_candidates),
        managed_http=len(managed_http),
        managed_checksum=len(managed_checksum),
        http_candidate_ids=[m.get("id") for m in http_candidates if isinstance(m, dict)],
        checksum_candidate_ids=[m.get("id") for m in checksum_candidates if isinstance(m, dict)],
    )

    if managed_http:
        http_mon = managed_http[0]
        if len(managed_http) > 1 and cfg.allow_delete_managed_duplicates:
            for dup in managed_http[1:]:
                if cfg.dry_run:
                    log_event("kuma_delete_duplicate", domain=domain, monitor_id=dup.get("id"), name=http_name, dry_run=True)
                    s = _summary()
                    if s is not None:
                        s.add_removed_monitor(source="managed_duplicate", domain=domain, monitor_id=dup.get("id"), name=http_name, dry_run=True)
                else:
                    kuma.delete_monitor(int(dup["id"]))
                    log_event("kuma_delete_duplicate", domain=domain, monitor_id=int(dup["id"]), name=http_name)
                    s = _summary()
                    if s is not None:
                        s.add_removed_monitor(source="managed_duplicate", domain=domain, monitor_id=int(dup["id"]), name=http_name, dry_run=False)
    elif http_candidates:
        http_mon = http_candidates[0]

    if managed_checksum:
        checksum_mon = managed_checksum[0]
        if len(managed_checksum) > 1 and cfg.allow_delete_managed_duplicates:
            for dup in managed_checksum[1:]:
                if cfg.dry_run:
                    log_event("kuma_delete_duplicate", domain=domain, monitor_id=dup.get("id"), name=checksum_name, dry_run=True)
                    s = _summary()
                    if s is not None:
                        s.add_removed_monitor(source="managed_duplicate", domain=domain, monitor_id=dup.get("id"), name=checksum_name, dry_run=True)
                else:
                    kuma.delete_monitor(int(dup["id"]))
                    log_event("kuma_delete_duplicate", domain=domain, monitor_id=int(dup["id"]), name=checksum_name)
                    s = _summary()
                    if s is not None:
                        s.add_removed_monitor(source="managed_duplicate", domain=domain, monitor_id=int(dup["id"]), name=checksum_name, dry_run=False)
    elif checksum_candidates:
        checksum_mon = checksum_candidates[0]

    http_parent = ensure_group_exists(kuma, cfg.http_group_id)
    checksum_parent = ensure_group_exists(kuma, cfg.checksum_group_id)

    if http_mon is None:
        monitor_obj: Dict[str, Any] = {
            "type": "http",
            "name": http_name,
            "url": f"https://{domain}",
            "method": "GET",
            "interval": cfg.http_interval,
            "retryInterval": cfg.http_interval,
            "maxretries": cfg.http_retries,
            "accepted_statuscodes": ["200-299"],
            "notificationIDList": [],
            "description": build_description(site_path, domain, "http"),
        }
        if http_parent is not None:
            monitor_obj["parent"] = http_parent
        if cfg.dry_run:
            http_id = -1
        else:
            http_id = kuma.add_monitor(monitor_obj)
            try:
                kuma.refresh_monitor_list()
            except Exception:
                pass
        log_event("kuma_http_monitor_create", domain=domain, monitor_id=http_id, name=http_name, dry_run=cfg.dry_run)
        s = _summary()
        if s is not None:
            s.add_created_monitor(kind="http", domain=domain, monitor_id=http_id, name=http_name, dry_run=cfg.dry_run)
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
        generated_push_token = secrets.token_hex(16)
        monitor_obj = {
            "type": "push",
            "name": checksum_name,
            "interval": cfg.push_interval,
            "accepted_statuscodes": ["200-299"],
            "notificationIDList": [],
            "pushToken": generated_push_token,
            "description": build_description(site_path, domain, "checksum"),
        }
        if checksum_parent is not None:
            monitor_obj["parent"] = checksum_parent
        if cfg.dry_run:
            checksum_id = -1
            push_token = ""
        else:
            checksum_id = kuma.add_monitor(monitor_obj)
            push_token = generated_push_token
            try:
                kuma.refresh_monitor_list()
            except Exception:
                pass
        log_event("kuma_checksum_monitor_create", domain=domain, monitor_id=checksum_id, name=checksum_name, dry_run=cfg.dry_run)
        s = _summary()
        if s is not None:
            s.add_created_monitor(kind="push", domain=domain, monitor_id=checksum_id, name=checksum_name, dry_run=cfg.dry_run)
    else:
        checksum_id = int(checksum_mon["id"])
        if cfg.dry_run:
            push_token = ""
        else:
            if cached_push_token:
                push_token = cached_push_token
            else:
                full = kuma.get_monitor(checksum_id)
                push_token = str(full.get("pushToken") or full.get("push_token") or "")

            if not push_token:
                new_token = secrets.token_hex(16)
                full = kuma.get_monitor(checksum_id)
                full["pushToken"] = new_token
                if checksum_parent is not None:
                    full["parent"] = checksum_parent
                kuma.edit_monitor(full)
                push_token = new_token
                log_event("kuma_push_token_set", domain=domain, monitor_id=checksum_id)

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

    if not cfg.kuma_verify_ssl:
        log_event(
            "kuma_ssl_verify_disabled",
            result="error",
            hint="SSL verification disabled; prefer using a hostname that matches the certificate",
        )
        s = _summary()
        if s is not None:
            s.inc("kuma_verify_ssl_disabled", 1)

    try:
        r = requests.get(
            f"{cfg.kuma_url}/api/entry-page",
            timeout=cfg.request_timeout,
            verify=bool(cfg.kuma_verify_ssl),
            allow_redirects=False,
        )
        if 300 <= int(r.status_code) < 400:
            loc = str(r.headers.get("Location") or "")
            if loc:
                raise RuntimeError(
                    f"kuma_url_redirect:{r.status_code};location={loc};hint=Set WPCHECK_KUMA_URL to the final scheme/host (e.g. https://...) to avoid redirects"
                )
            raise RuntimeError(
                f"kuma_url_redirect:{r.status_code};hint=Set WPCHECK_KUMA_URL to the final scheme/host (e.g. https://...) to avoid redirects"
            )
        if r.status_code >= 400:
            raise RuntimeError(f"kuma_unreachable_http_{r.status_code}")
    except requests.exceptions.SSLError as e:
        raise RuntimeError(
            "kuma_ssl_verify_failed:"
            + str(e)
            + ";hint=Set WPCHECK_KUMA_URL to a hostname that matches the certificate, or set WPCHECK_KUMA_VERIFY_SSL=false (insecure)"
        )
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
        missing_domain = False
        quarantine_domain = domain
        if not domain:
            missing_domain = True
            base = (os.path.basename(os.path.normpath(site_path)) or "site").strip().lower()
            base = "".join(c if (c.isalnum() or c in {"-", "_", "."}) else "_" for c in base)[:60] or "site"
            digest = hashlib.sha1(site_path.encode("utf-8")).hexdigest()[:10]
            quarantine_domain = f"missing-domain-{base}-{digest}"
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
                rel_path_clean = rel_path.lstrip("/\\")
                src = os.path.normpath(os.path.join(site_path, rel_path_clean))
                try:
                    dst = quarantine_file(site_path, cfg.quarantine_dir, str(quarantine_domain), rel_path, cfg.dry_run)
                    quarantined.append((rel_path, dst))
                    if dst is None:
                        log_event(
                            "quarantine_missing_source",
                            result="error",
                            domain=str(quarantine_domain),
                            site_path=site_path,
                            rel_path=rel_path,
                            src=src,
                            src_exists=os.path.exists(src),
                            dry_run=cfg.dry_run,
                        )
                    else:
                        moved_ok = True
                        if not cfg.dry_run:
                            moved_ok = os.path.exists(dst) and not os.path.exists(src)
                        log_event(
                            "quarantine_moved",
                            result="ok" if moved_ok else "error",
                            domain=str(quarantine_domain),
                            site_path=site_path,
                            rel_path=rel_path,
                            src=src,
                            dst=dst,
                            moved_ok=moved_ok,
                            dry_run=cfg.dry_run,
                        )
                except Exception as e:
                    quarantined.append((rel_path, None))
                    log_event(
                        "quarantine_failed",
                        result="error",
                        domain=str(quarantine_domain),
                        site_path=site_path,
                        rel_path=rel_path,
                        src=src,
                        error=str(e),
                    )

            if not suspicious:
                log_event("quarantine_no_matches", domain=str(quarantine_domain), site_path=site_path)

            if suspicious and not cfg.dry_run:
                out, err, rc = run_wp(
                    cfg.wpcli,
                    site_path,
                    ["core", "verify-checksums", "--allow-root", "--skip-plugins", "--skip-themes"],
                    cfg.wp_timeout,
                )
                failed = checksum_failed(out, err, rc)

        return SiteResult(
            site_path=site_path,
            domain=domain,
            ignored=False,
            checksum_failed=failed,
            quarantined=quarantined,
            error="missing_domain" if missing_domain else None,
        )
    except subprocess.TimeoutExpired:
        return SiteResult(site_path=site_path, domain=None, ignored=False, checksum_failed=True, quarantined=quarantined, error="wp_timeout")
    except Exception as e:
        return SiteResult(site_path=site_path, domain=None, ignored=False, checksum_failed=True, quarantined=quarantined, error=str(e))


# ---------------- ARGPARSE ----------------
parser = argparse.ArgumentParser()
parser.add_argument("--limit", type=int, default=0, help="Limit number of sites to scan (0 = all)")
parser.add_argument("--cleanup-only", action="store_true", help="Only cleanup ignored sites (managed monitors only)")
parser.add_argument("--cleanup-ignored", action="store_true", help="Delete managed monitors for ignored domains")
parser.add_argument("--prune-orphans", action="store_true", help="Delete wpcheck monitoring data for orphaned sites (missing wp_path/site_path)")
parser.add_argument("--workers", type=int, default=None, help="Number of concurrent WP workers")
parser.add_argument("--dry-run", action="store_true", help="Do not modify Kuma or filesystem")
args = parser.parse_args()


def main() -> int:
    cfg = load_config(args)

    if not cfg.kuma_verify_ssl:
        try:
            import urllib3  # type: ignore
            from urllib3.exceptions import InsecureRequestWarning  # type: ignore

            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

    log_event("config_kuma", kuma_url=cfg.kuma_url, kuma_verify_ssl=bool(cfg.kuma_verify_ssl))
    preflight(cfg)

    cache = read_cache(cfg.cache_file)
    ignored_list = read_ignore_list(cfg.ignore_file)
    ignored_set = build_ignored_set(ignored_list)

    global RUN_SUMMARY
    mode = "scan"
    if args.cleanup_only:
        mode = "cleanup_only"
    if args.prune_orphans:
        mode = "prune_orphans"
    RUN_SUMMARY = RunSummary.new(mode=mode, dry_run=cfg.dry_run)

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

        if args.prune_orphans:
            prune_orphan_monitoring_data(kuma, cfg, cache)
            s = _summary()
            if s is not None:
                s.inc("ignored_entries", len(set(ignored_list)))
            print_run_summary(cfg, RUN_SUMMARY)
            return 0

        if args.cleanup_only:
            if not cfg.allow_delete_ignored_managed:
                log_event("cleanup_skipped", result="error", error="cleanup_requires_flag", hint="use --cleanup-ignored")
                print_run_summary(cfg, RUN_SUMMARY)
                return 2

            for domain in sorted(set(ignored_list)):
                cleanup_ignored_domain(kuma, cfg, cache, domain)
            s = _summary()
            if s is not None:
                s.inc("ignored_entries", len(set(ignored_list)))
            print_run_summary(cfg, RUN_SUMMARY)
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
        missing_domain_count = 0
        ignored_count = 0
        processed_count = 0

        with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
            futures = {ex.submit(process_site, cfg, site, ignored_set): site for site in sites}
            for fut in as_completed(futures):
                res = fut.result()
                processed_count += 1
                s = _summary()
                if s is not None:
                    s.inc("sites_processed", 1)
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
                        checksum_failed=res.checksum_failed,
                        quarantined=len(res.quarantined),
                        error=res.error or "unknown",
                    )
                    if res.error == "missing_domain":
                        missing_domain_count += 1
                        if s is not None:
                            s.inc("missing_domain", 1)

                if res.ignored:
                    ignored_count += 1
                    if s is not None:
                        s.inc("sites_ignored", 1)

                if res.quarantined:
                    if s is not None:
                        for rel_path, dst in res.quarantined:
                            s.add_quarantine(
                                domain=res.domain or "",
                                site_path=res.site_path,
                                rel_path=rel_path,
                                dst=dst or "",
                                dry_run=cfg.dry_run,
                            )

                if res.error and s is not None:
                    s.add_error(res.error)

                if res.ignored and res.domain and cfg.allow_delete_ignored_managed:
                    cleanup_ignored_domain(kuma, cfg, cache, res.domain)

                if res.ignored or not res.domain:
                    continue

                domain = res.domain
                def _ensure():
                    cached_token = str(cache.get(domain, {}).get("checksum_token") or "")
                    return ensure_domain_monitors(
                        kuma,
                        cfg,
                        domain=domain,
                        site_path=res.site_path,
                        cached_push_token=cached_token or None,
                    )

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
                    lambda: send_push(
                        cfg.kuma_url,
                        push_token,
                        status=status,
                        msg=msg,
                        timeout_s=cfg.request_timeout,
                        verify_ssl=cfg.kuma_verify_ssl,
                    ),
                    retries=3,
                    base_delay=1,
                    max_delay=10,
                    action="kuma_push",
                    domain=domain,
                )
                if res.checksum_failed:
                    failed_sites[domain] = res.site_path
                    if s is not None:
                        s.inc("checksum_failed", 1)

        if cfg.missing_domain_push_token and not cfg.dry_run:
            status = "up"
            if cfg.missing_domain_alert_threshold > 0 and missing_domain_count > cfg.missing_domain_alert_threshold:
                status = "down"
            retry(
                lambda: send_push(
                    cfg.kuma_url,
                    cfg.missing_domain_push_token,
                    status=status,
                    msg=f"missing_domain={missing_domain_count};sites={len(sites)}",
                    timeout_s=cfg.request_timeout,
                    verify_ssl=cfg.kuma_verify_ssl,
                ),
                retries=3,
                base_delay=1,
                max_delay=10,
                action="kuma_missing_domain_metric",
                missing_domain_count=missing_domain_count,
            )
            log_event(
                "missing_domain_metric",
                missing_domain_count=missing_domain_count,
                sites=len(sites),
                threshold=cfg.missing_domain_alert_threshold,
            )

        log_event("scan_complete", failed=len(failed_sites), missing_domain_count=missing_domain_count)
        for d, p in sorted(failed_sites.items()):
            log_event("checksum_failure", result="error", domain=d, site_path=p)

        s = _summary()
        if s is not None:
            s.inc("sites_total", len(sites))
            s.inc("sites_processed_final", processed_count)
            s.inc("sites_ignored_final", ignored_count)
            s.inc("checksum_failed_domains", len(failed_sites))
            s.inc("missing_domain_final", missing_domain_count)
        print_run_summary(cfg, RUN_SUMMARY)
        return 1 if failed_sites else 0
    finally:
        kuma.disconnect()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log_event("fatal", result="error", error=str(e), error_type=type(e).__name__, error_repr=repr(e))
        sys.exit(2)
