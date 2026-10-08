"""
app.py
======
Secure Hybrid Network & Server Monitoring Dashboard - Flask backend.

What this service does
----------------------
* Checks the health of three kinds of infrastructure targets:
    - ``ip``  : ICMP echo via the OS ``ping`` binary (subprocess), with an
                automatic TCP-connect fallback when ICMP is blocked or the
                ``ping`` binary is unavailable (typical on PaaS containers).
    - ``dns`` : a real DNS query (hand-built UDP packet on port 53) to verify the
                resolver actually answers - not just that the host is up.
    - ``url`` : HTTP(S) request with strict timeouts.
* Runs all checks in parallel and records every result in the database.
* Exposes a small REST API consumed by the dashboard (templates/index.html).
* Optionally runs a background scheduler so history keeps building even when
  nobody has the dashboard open.

Endpoints
---------
    GET /                 dashboard UI
    GET /api/status       run (or reuse a fresh) scan, log it, return current state
    GET /api/logs         historical records from the database
    GET /api/health       lightweight liveness probe for hosting platforms
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

load_dotenv()  # read a local .env file (if present) before configuration is evaluated

import db_config  # noqa: E402  (deliberately imported after load_dotenv)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Environment helpers
# --------------------------------------------------------------------------- #
def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Logging (console + rotating files, separate file for errors)
# --------------------------------------------------------------------------- #
logger = logging.getLogger("netmon")


def configure_logging() -> None:
    """Configure the ``netmon`` logger tree once. Child loggers (netmon.db) inherit it."""
    if logger.handlers:
        return

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        log_dir = os.getenv("LOG_DIR", os.path.join(BASE_DIR, "logs"))
        os.makedirs(log_dir, exist_ok=True)

        main_file = RotatingFileHandler(
            os.path.join(log_dir, "netmon.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        main_file.setFormatter(formatter)
        logger.addHandler(main_file)

        error_file = RotatingFileHandler(
            os.path.join(log_dir, "netmon-errors.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        logger.addHandler(error_file)
    except OSError as exc:
        # Read-only filesystems exist on some hosts; console logging still works.
        logger.warning("File logging disabled (%s). Continuing with console logging only.", exc)


configure_logging()


# --------------------------------------------------------------------------- #
# Application settings
# --------------------------------------------------------------------------- #
DEFAULT_TIMEOUT = _env_float("SCAN_TIMEOUT_SECONDS", 3.0, minimum=0.5)       # ICMP / TCP / DNS
HTTP_TIMEOUT = _env_float("HTTP_TIMEOUT_SECONDS", 5.0, minimum=0.5)          # HTTP(S) checks
REFRESH_SECONDS = _env_int("REFRESH_INTERVAL_SECONDS", 15, minimum=5)        # dashboard poll period
SCAN_CACHE_TTL = _env_float("SCAN_CACHE_TTL_SECONDS", 10.0)                  # reuse results this long
MIN_FORCE_INTERVAL = 2.0                                                      # anti-spam for "Force scan"
MAX_WORKERS = _env_int("MAX_SCAN_WORKERS", 16, minimum=1)
ENABLE_BACKGROUND_SCHEDULER = _env_bool("ENABLE_BACKGROUND_SCHEDULER", False)
BACKGROUND_SCAN_SECONDS = _env_int("BACKGROUND_SCAN_SECONDS", 60, minimum=10)
LOG_RETENTION_DAYS = _env_int("LOG_RETENTION_DAYS", 30)                      # 0 disables purging
PURGE_EVERY_SECONDS = 3600
MAX_LOG_LIMIT = 1000

HTTP_HEADERS = {
    "User-Agent": "SecureNetworkMonitor/1.0 (+availability-check)",
    "Accept": "*/*",
}


# --------------------------------------------------------------------------- #
# Target loading and validation
# --------------------------------------------------------------------------- #
DEFAULT_TARGETS: List[Dict[str, Any]] = [
    {"name": "Google Public DNS", "address": "8.8.8.8", "type": "dns", "query_domain": "google.com"},
    {"name": "Cloudflare DNS", "address": "1.1.1.1", "type": "dns", "query_domain": "cloudflare.com"},
    {"name": "Cloudflare Edge", "address": "1.1.1.1", "type": "ip", "method": "icmp", "port": 443},
    {"name": "GitHub", "address": "https://github.com", "type": "url"},
]

VALID_TYPES = {"ip", "dns", "url"}

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _is_valid_host(value: str) -> bool:
    """True for a literal IPv4/IPv6 address or a syntactically valid hostname.

    Validation also guarantees a value can never be mistaken for a command-line
    option when it is passed to ``ping`` (no leading dash, no whitespace).
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalise_target(raw: Any, index: int) -> Optional[Dict[str, Any]]:
    """Validate one entry from targets.json. Returns None (and logs why) if unusable."""
    if not isinstance(raw, dict):
        logger.warning("Target #%d ignored: expected an object.", index)
        return None

    target_type = str(raw.get("type", "")).strip().lower()
    address = str(raw.get("address", "")).strip()
    name = str(raw.get("name") or address).strip()[:120]

    if target_type not in VALID_TYPES or not address:
        logger.warning("Target #%d ignored: needs a valid 'type' (ip|dns|url) and an 'address'.", index)
        return None

    default_timeout = HTTP_TIMEOUT if target_type == "url" else DEFAULT_TIMEOUT
    try:
        timeout = float(raw.get("timeout", default_timeout))
    except (TypeError, ValueError):
        timeout = default_timeout
    timeout = min(max(timeout, 0.5), 30.0)

    target: Dict[str, Any] = {"name": name, "address": address, "type": target_type, "timeout": timeout}

    if target_type == "url":
        parsed = urlparse(address)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            logger.warning("Target '%s' ignored: URL must start with http:// or https://.", name)
            return None
        max_status = _to_int(raw.get("max_status"))
        target["max_status"] = max_status if max_status is not None else 399
        return target

    if not _is_valid_host(address):
        logger.warning("Target '%s' ignored: '%s' is not a valid IP address or hostname.", name, address)
        return None

    if target_type == "ip":
        method = str(raw.get("method", "icmp")).strip().lower()
        target["method"] = method if method in {"icmp", "tcp"} else "icmp"
        port = _to_int(raw.get("port"))
        target["port"] = port if port is not None and 1 <= port <= 65535 else None
        if target["method"] == "tcp" and target["port"] is None:
            target["port"] = 443
    else:  # dns
        domain = str(raw.get("query_domain", "google.com")).strip().lower()
        target["query_domain"] = domain if _HOSTNAME_RE.match(domain) else "google.com"

    return target


def load_targets() -> List[Dict[str, Any]]:
    """Load targets from TARGETS_JSON (inline), TARGETS_FILE, or ./targets.json."""
    inline = os.getenv("TARGETS_JSON")
    path = os.getenv("TARGETS_FILE", os.path.join(BASE_DIR, "targets.json"))

    data: Any = DEFAULT_TARGETS
    try:
        if inline:
            data = json.loads(inline)
            logger.info("Loaded targets from TARGETS_JSON environment variable.")
        elif os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            logger.info("Loaded targets from %s", path)
        else:
            logger.warning("No targets file found at %s; using built-in defaults.", path)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Could not read targets configuration (%s); using built-in defaults.", exc)
        data = DEFAULT_TARGETS

    if not isinstance(data, list):
        logger.error("Targets configuration must be a JSON array; using built-in defaults.")
        data = DEFAULT_TARGETS

    targets: List[Dict[str, Any]] = []
    seen_names = set()
    for index, raw in enumerate(data, start=1):
        target = normalise_target(raw, index)
        if target is None:
            continue
        if target["name"] in seen_names:  # names key the history chart, so keep them unique
            target["name"] = f"{target['name']} ({target['address']})"[:120]
        seen_names.add(target["name"])
        targets.append(target)

    if not targets:
        logger.error("No valid targets configured; falling back to built-in defaults.")
        return [t for i, raw in enumerate(DEFAULT_TARGETS, 1) if (t := normalise_target(raw, i))]
    return targets


TARGETS: List[Dict[str, Any]] = load_targets()


# --------------------------------------------------------------------------- #
# Health checks
# --------------------------------------------------------------------------- #
@dataclass
class CheckResult:
    status: str                       # "ONLINE" | "OFFLINE"
    response_time_ms: Optional[float]
    detail: str


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


# ---- TCP --------------------------------------------------------------------
def tcp_check(host: str, port: int, timeout: float) -> CheckResult:
    """Measure a full TCP three-way handshake to host:port."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult("ONLINE", _elapsed_ms(start), f"TCP {port} handshake succeeded")
    except socket.timeout:
        return CheckResult("OFFLINE", None, f"TCP {port} timed out after {timeout:g}s")
    except socket.gaierror:
        return CheckResult("OFFLINE", None, "DNS resolution failed")
    except OSError as exc:
        return CheckResult("OFFLINE", None, f"TCP {port} failed: {exc.strerror or exc}")


# ---- ICMP (subprocess) ----------------------------------------------------------
_PING_TIME_RE = re.compile(r"time\s*[=<]\s*([\d.,]+)\s*ms", re.IGNORECASE)


def _build_ping_command(ping_bin: str, host: str, timeout: float) -> List[str]:
    """Build the correct single-echo ping command for the current operating system."""
    system = platform.system().lower()
    if system == "windows":
        return [ping_bin, "-n", "1", "-w", str(int(timeout * 1000)), host]  # -w is milliseconds
    if system == "darwin":
        return [ping_bin, "-c", "1", "-W", str(int(timeout * 1000)), host]  # macOS -W is milliseconds
    return [ping_bin, "-c", "1", "-W", str(max(1, math.ceil(timeout))), host]  # Linux -W is seconds


def icmp_check(host: str, timeout: float) -> Optional[CheckResult]:
    """Ping ``host`` with the OS ping utility.

    Returns:
        CheckResult - ICMP could be attempted (the result may be ONLINE or OFFLINE)
        None        - ICMP is unavailable here (no ping binary / not permitted), so the
                      caller should fall back to another technique.
    """
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return None

    command = _build_ping_command(ping_bin, host, timeout)
    start = time.perf_counter()
    try:
        completed = subprocess.run(  # noqa: S603 - argument list, never a shell, host is validated
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout + 2,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),  # no console flash on Windows
        )
    except subprocess.TimeoutExpired:
        return CheckResult("OFFLINE", None, f"ICMP timed out after {timeout:g}s")
    except (FileNotFoundError, PermissionError, OSError) as exc:
        logger.warning("ICMP unavailable (%s); falling back to TCP.", exc)
        return None

    output = f"{completed.stdout}\n{completed.stderr}"
    # A TTL field only appears in a genuine echo reply (Windows can exit 0 on
    # "Destination host unreachable", so the exit code alone is not enough).
    if completed.returncode == 0 and "ttl" in output.lower():
        match = _PING_TIME_RE.search(output)
        if match:
            try:
                return CheckResult("ONLINE", round(float(match.group(1).replace(",", ".")), 2), "ICMP echo reply")
            except ValueError:
                pass
        return CheckResult("ONLINE", _elapsed_ms(start), "ICMP echo reply")

    # "Operation not permitted" means ICMP is sandboxed here, not that the host is down.
    if "not permitted" in output.lower() or "permission denied" in output.lower():
        return None
    return CheckResult("OFFLINE", None, "No ICMP echo reply")


def ip_check(target: Dict[str, Any]) -> CheckResult:
    """ICMP first (when configured), then TCP fallback so cloud-hosted instances still work."""
    host, timeout, port = target["address"], target["timeout"], target.get("port")

    if target.get("method") == "tcp":
        return tcp_check(host, port or 443, timeout)

    icmp = icmp_check(host, timeout)
    if icmp is not None and icmp.status == "ONLINE":
        return icmp

    if port:
        tcp = tcp_check(host, port, timeout)
        if tcp.status == "ONLINE":
            reason = "ICMP unavailable" if icmp is None else "ICMP blocked"
            return CheckResult("ONLINE", tcp.response_time_ms, f"{tcp.detail} ({reason})")
        return tcp

    if icmp is None:
        # No ICMP and no configured port: probe the two most common ports as a last resort.
        for fallback_port in (443, 80):
            tcp = tcp_check(host, fallback_port, timeout)
            if tcp.status == "ONLINE":
                return CheckResult("ONLINE", tcp.response_time_ms, f"{tcp.detail} (ICMP unavailable)")
        return CheckResult("OFFLINE", None, "ICMP unavailable and TCP 443/80 closed")
    return icmp


# ---- DNS (raw UDP) ----------------------------------------------------------------
def _build_dns_query(domain: str) -> "tuple[int, bytes]":
    """Build a minimal DNS A-record query packet (RFC 1035)."""
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)  # RD flag set, 1 question
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in domain.strip(".").split(".")
    )
    question = qname + b"\x00" + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return transaction_id, header + question


def dns_check(target: Dict[str, Any]) -> CheckResult:
    """Ask the DNS server to resolve a domain and validate the reply."""
    host, timeout = target["address"], target["timeout"]
    domain = target.get("query_domain", "google.com")

    try:
        family, _, _, _, sockaddr = socket.getaddrinfo(host, 53, type=socket.SOCK_DGRAM)[0]
    except socket.gaierror:
        return CheckResult("OFFLINE", None, "Could not resolve DNS server address")

    transaction_id, packet = _build_dns_query(domain)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            start = time.perf_counter()
            sock.sendto(packet, sockaddr)
            data, _ = sock.recvfrom(1024)
            elapsed = _elapsed_ms(start)
    except socket.timeout:
        return CheckResult("OFFLINE", None, f"DNS query timed out after {timeout:g}s")
    except OSError as exc:
        return CheckResult("OFFLINE", None, f"DNS query failed: {exc.strerror or exc}")

    if len(data) < 12:
        return CheckResult("OFFLINE", None, "Malformed DNS reply")
    reply_id, flags = struct.unpack("!HH", data[:4])
    if reply_id != transaction_id:
        return CheckResult("OFFLINE", None, "DNS reply did not match the query")
    if not flags & 0x8000:
        return CheckResult("OFFLINE", None, "Response was not a DNS answer")
    rcode = flags & 0x000F
    if rcode != 0:
        return CheckResult("OFFLINE", None, f"DNS server returned error code {rcode}")
    return CheckResult("ONLINE", elapsed, f"Resolved {domain}")


# ---- HTTP(S) --------------------------------------------------------------------
def url_check(target: Dict[str, Any]) -> CheckResult:
    """GET the URL (headers only, body not downloaded) and judge by status code."""
    timeout = target["timeout"]
    start = time.perf_counter()
    try:
        with requests.get(
            target["address"],
            headers=HTTP_HEADERS,
            timeout=(timeout, timeout),  # (connect, read) - never hang on a dead endpoint
            allow_redirects=True,
            stream=True,
        ) as response:
            elapsed = _elapsed_ms(start)
            code = response.status_code
    except requests.exceptions.Timeout:
        return CheckResult("OFFLINE", None, f"HTTP request timed out after {timeout:g}s")
    except requests.exceptions.SSLError:
        return CheckResult("OFFLINE", None, "TLS/SSL certificate error")
    except requests.exceptions.TooManyRedirects:
        return CheckResult("OFFLINE", None, "Too many redirects")
    except requests.exceptions.ConnectionError:
        return CheckResult("OFFLINE", None, "Connection failed (DNS error or refused)")
    except requests.exceptions.RequestException as exc:
        return CheckResult("OFFLINE", None, f"HTTP error: {exc.__class__.__name__}")

    if code <= target["max_status"]:
        return CheckResult("ONLINE", elapsed, f"HTTP {code}")
    return CheckResult("OFFLINE", None, f"HTTP {code}")


# ---- Dispatcher -------------------------------------------------------------------
def run_check(target: Dict[str, Any]) -> Dict[str, Any]:
    """Run the right check for a target. Never raises - one bad target must not break a scan."""
    try:
        if target["type"] == "ip":
            result = ip_check(target)
        elif target["type"] == "dns":
            result = dns_check(target)
        else:
            result = url_check(target)
    except Exception as exc:  # noqa: BLE001 - last line of defence for the scan loop
        logger.exception("Unexpected error while checking '%s'", target["name"])
        result = CheckResult("OFFLINE", None, f"Internal error: {exc.__class__.__name__}")

    return {
        "name": target["name"],
        "address": target["address"],
        "type": target["type"],
        "status": result.status,
        "response_time_ms": result.response_time_ms,
        "detail": result.detail,
    }


# --------------------------------------------------------------------------- #
# Scan orchestration, caching and persistence
# --------------------------------------------------------------------------- #
_scan_lock = threading.Lock()          # one scan at a time; concurrent callers reuse its result
_last_payload: Optional[Dict[str, Any]] = None
_last_scan_at = 0.0                    # time.monotonic() of the last completed scan
_last_purge_at = 0.0


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    online = sum(1 for r in results if r["status"] == "ONLINE")
    latencies = [
        r["response_time_ms"]
        for r in results
        if r["status"] == "ONLINE" and r["response_time_ms"] is not None
    ]
    availability = round(online / total * 100, 1) if total else 0.0
    if total and online == total:
        health = "healthy"
    elif availability >= 50:
        health = "degraded"
    else:
        health = "critical"
    return {
        "total": total,
        "online": online,
        "offline": total - online,
        "availability_pct": availability,
        "avg_response_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "health": health,
    }


def _maybe_purge() -> None:
    """Apply the retention policy at most once per hour."""
    global _last_purge_at
    if LOG_RETENTION_DAYS <= 0 or time.monotonic() - _last_purge_at < PURGE_EVERY_SECONDS:
        return
    _last_purge_at = time.monotonic()
    try:
        removed = db_config.purge_old_logs(LOG_RETENTION_DAYS)
        if removed:
            logger.info("Retention policy removed %d records older than %d days.", removed, LOG_RETENTION_DAYS)
    except db_config.DatabaseError as exc:
        logger.error("Retention clean-up failed: %s", exc)


def _scan_and_log() -> Dict[str, Any]:
    """Check every target in parallel, persist the results, and build the API payload."""
    scanned_at = datetime.now(timezone.utc)  # one timestamp per scan keeps history aligned
    started = time.perf_counter()

    workers = max(1, min(MAX_WORKERS, len(TARGETS)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netmon-check") as pool:
        results = list(pool.map(run_check, TARGETS))

    records = [
        {
            "scanned_at": scanned_at,
            "host_name": r["name"],
            "ip_address": r["address"],
            "target_type": r["type"],
            "status": r["status"],
            "response_time_ms": r["response_time_ms"],
        }
        for r in results
    ]

    db_info: Dict[str, Any] = {"backend": db_config.get_backend_name(), "logged": False}
    try:
        db_info["rows"] = db_config.insert_logs(records)
        db_info["logged"] = True
    except db_config.DatabaseError as exc:
        logger.error("Could not persist scan results: %s", exc)
        db_info["error"] = "Database unavailable - this scan was not stored."
    else:
        _maybe_purge()

    summary = build_summary(results)
    for r in results:
        if r["status"] == "OFFLINE":
            logger.warning("Target OFFLINE: %s (%s) - %s", r["name"], r["address"], r["detail"])
    logger.info(
        "Scan complete: %d/%d online in %.0f ms (stored=%s)",
        summary["online"],
        summary["total"],
        (time.perf_counter() - started) * 1000,
        db_info["logged"],
    )

    return {
        "scanned_at": _iso(scanned_at),
        "summary": summary,
        "targets": results,
        "db": db_info,
        "refresh_interval": REFRESH_SECONDS,
    }


def get_status(force: bool = False) -> Dict[str, Any]:
    """Return the current state, scanning only when the cached result is stale.

    Many browsers polling every 15 s must not multiply the load on the monitored
    infrastructure, so results younger than SCAN_CACHE_TTL are reused. A forced
    scan bypasses that cache but is still rate-limited to MIN_FORCE_INTERVAL.
    """
    global _last_payload, _last_scan_at
    with _scan_lock:
        age = time.monotonic() - _last_scan_at
        ttl = MIN_FORCE_INTERVAL if force else SCAN_CACHE_TTL
        if _last_payload is not None and age < ttl:
            return {**_last_payload, "cached": True, "cache_age_seconds": round(age, 1)}

        payload = _scan_and_log()
        _last_payload = payload
        _last_scan_at = time.monotonic()
        return {**payload, "cached": False, "cache_age_seconds": 0.0}


# --------------------------------------------------------------------------- #
# Optional background scheduler
# --------------------------------------------------------------------------- #
_stop_event = threading.Event()
_scheduler_thread: Optional[threading.Thread] = None


def _scheduler_loop() -> None:
    logger.info("Background scheduler started (every %ds).", BACKGROUND_SCAN_SECONDS)
    while not _stop_event.is_set():
        try:
            get_status(force=False)
        except Exception:  # noqa: BLE001 - the loop must survive any single failure
            logger.exception("Background scan failed")
        _stop_event.wait(BACKGROUND_SCAN_SECONDS)


def start_background_scheduler() -> None:
    """Start the scheduler thread once per process (no-op when disabled)."""
    global _scheduler_thread
    if not ENABLE_BACKGROUND_SCHEDULER or _scheduler_thread is not None:
        return
    _scheduler_thread = threading.Thread(target=_scheduler_loop, name="netmon-scheduler", daemon=True)
    _scheduler_thread.start()


# --------------------------------------------------------------------------- #
# Flask application
# --------------------------------------------------------------------------- #
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "*")}})


@app.after_request
def add_security_headers(response):
    """Baseline hardening headers for every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    """Serve the dashboard."""
    return render_template(
        "index.html",
        refresh_seconds=REFRESH_SECONDS,
        db_backend=db_config.get_backend_name(),
    )


@app.route("/api/status")
def api_status():
    """Run (or reuse) a scan, store it in the database, and return the current state."""
    force = request.args.get("force", "").strip().lower() in {"1", "true", "yes"}
    try:
        return jsonify(get_status(force=force))
    except Exception:  # noqa: BLE001
        logger.exception("Scan request failed")
        return jsonify({"error": "The scan could not be completed. Check the server logs."}), 500


@app.route("/api/logs")
def api_logs():
    """Return historical scan records (newest first). Optional: limit, host, status."""
    limit = request.args.get("limit", default=100, type=int) or 100
    limit = max(1, min(limit, MAX_LOG_LIMIT))
    host = (request.args.get("host") or "").strip()[:120] or None
    status = (request.args.get("status") or "").strip().upper()
    if status not in {"ONLINE", "OFFLINE"}:
        status = None

    try:
        logs = db_config.fetch_logs(limit=limit, host=host, status=status)
    except db_config.DatabaseError as exc:
        logger.error("Could not read logs: %s", exc)
        return jsonify({"error": "Database unavailable.", "count": 0, "logs": []}), 503
    return jsonify({"count": len(logs), "logs": logs, "backend": db_config.get_backend_name()})


@app.route("/api/health")
def api_health():
    """Cheap liveness probe (does not touch the network or the database)."""
    return jsonify({"status": "ok", "time": _iso(datetime.now(timezone.utc)), "targets": len(TARGETS)})


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return "Page not found.", 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(500)
def server_error(error):
    logger.error("Unhandled server error: %s", error)
    return jsonify({"error": "Internal server error."}), 500


# --------------------------------------------------------------------------- #
# Start-up
# --------------------------------------------------------------------------- #
try:
    db_config.init_db()
except db_config.DatabaseError as exc:
    # The dashboard still runs; storage is retried automatically on the next scan.
    logger.error("Database initialisation failed: %s", exc)

start_background_scheduler()


if __name__ == "__main__":
    port = _env_int("PORT", 5000, minimum=1)
    host = os.getenv("HOST", "127.0.0.1")
    logger.info("Starting development server on http://%s:%d", host, port)
    app.run(host=host, port=port, debug=_env_bool("FLASK_DEBUG", False), use_reloader=False)
