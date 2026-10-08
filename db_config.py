"""
db_config.py
============
Database abstraction layer for the Secure Hybrid Network & Server Monitoring
Dashboard.

One module, three interchangeable storage engines. The engine is selected with
the ``DB_BACKEND`` environment variable:

    DB_BACKEND=sqlite    (default) zero-configuration, ideal for local demos
    DB_BACKEND=mysql     relational storage via a MySQL connection pool
    DB_BACKEND=mongodb   document storage via PyMongo (MongoDB / Atlas)

Public helper functions (the only API the Flask app needs):

    init_db()                 -> create schema / indexes, verify connectivity
    insert_logs(records)      -> persist one scan (list of record dicts)
    fetch_logs(limit, ...)    -> read historical records, newest first
    purge_old_logs(days)      -> retention clean-up
    get_backend_name()        -> "sqlite" | "mysql" | "mongodb"
    close_db()                -> release connections on shutdown

A *record* is a dict with these keys:

    scanned_at        timezone-aware datetime (UTC)
    host_name         str   - friendly name of the monitored target
    ip_address        str   - IP, hostname or URL that was checked
    target_type       str   - "ip" | "dns" | "url"
    status            str   - "ONLINE" | "OFFLINE"
    response_time_ms  float | None

All credentials are read from environment variables so that no secret is ever
committed to source control. See ``.env.example`` for the full list.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("netmon.db")

TABLE_NAME = "scan_logs"
Record = Dict[str, Any]


class DatabaseError(Exception):
    """Raised for any failure in the persistence layer (connect, read, write)."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _env(*names: str, default: Optional[str] = None) -> Optional[str]:
    """Return the first non-empty environment variable among ``names``.

    Several names are accepted so that platform-injected variables (for example
    Railway's ``MYSQLHOST``) work alongside the project's own ``MYSQL_HOST``.
    """
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid integer for %s; falling back to %s", name, default)
        return default


def _as_utc(value: datetime) -> datetime:
    """Normalise a datetime to timezone-aware UTC (naive values are assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    """Fixed-width ISO-8601 UTC string, e.g. 2026-10-08T09:30:00.123Z.

    The fixed width makes the strings sort chronologically as plain text, which
    SQLite relies on.
    """
    return _as_utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Backend interface
# --------------------------------------------------------------------------- #
class BaseBackend(ABC):
    """Contract that every storage engine implements."""

    name: str = "base"

    @abstractmethod
    def init(self) -> None:
        """Create the schema/indexes and verify that the database is reachable."""

    @abstractmethod
    def insert_many(self, records: List[Record]) -> int:
        """Insert records and return the number of rows written."""

    @abstractmethod
    def fetch(self, limit: int, host: Optional[str], status: Optional[str]) -> List[Record]:
        """Return up to ``limit`` records, newest scan first."""

    @abstractmethod
    def purge_older_than(self, cutoff: datetime) -> int:
        """Delete records older than ``cutoff`` and return how many were removed."""

    def close(self) -> None:  # pragma: no cover - optional hook
        """Release connections. Default: nothing to release."""


# --------------------------------------------------------------------------- #
# SQLite backend (default, standard library only)
# --------------------------------------------------------------------------- #
class SQLiteBackend(BaseBackend):
    name = "sqlite"

    def __init__(self) -> None:
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netmon.db")
        self.path = _env("SQLITE_PATH", default=default_path)
        self._lock = threading.Lock()  # serialise writers; SQLite allows one at a time

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with self._lock, closing(self._connect()) as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at       TEXT    NOT NULL,
                    host_name        TEXT    NOT NULL,
                    ip_address       TEXT    NOT NULL,
                    target_type      TEXT    NOT NULL,
                    status           TEXT    NOT NULL,
                    response_time_ms REAL
                )
                """
            )
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_scanned_at ON {TABLE_NAME} (scanned_at)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_host_name ON {TABLE_NAME} (host_name)")
            conn.commit()

    def insert_many(self, records: List[Record]) -> int:
        rows = [
            (
                _iso(r["scanned_at"]),
                r["host_name"],
                r["ip_address"],
                r["target_type"],
                r["status"],
                r["response_time_ms"],
            )
            for r in records
        ]
        with self._lock, closing(self._connect()) as conn:
            conn.executemany(
                f"""INSERT INTO {TABLE_NAME}
                    (scanned_at, host_name, ip_address, target_type, status, response_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                rows,
            )
            conn.commit()
        return len(rows)

    def fetch(self, limit: int, host: Optional[str], status: Optional[str]) -> List[Record]:
        clauses: List[str] = []
        params: List[Any] = []
        if host:
            clauses.append("host_name = ?")
            params.append(host)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT id, scanned_at, host_name, ip_address, target_type, status, response_time_ms "
            f"FROM {TABLE_NAME}{where} ORDER BY scanned_at DESC, id ASC LIMIT ?"
        )
        params.append(limit)
        with closing(self._connect()) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def purge_older_than(self, cutoff: datetime) -> int:
        with self._lock, closing(self._connect()) as conn:
            cursor = conn.execute(f"DELETE FROM {TABLE_NAME} WHERE scanned_at < ?", (_iso(cutoff),))
            conn.commit()
            return cursor.rowcount


# --------------------------------------------------------------------------- #
# MySQL backend
# --------------------------------------------------------------------------- #
class MySQLBackend(BaseBackend):
    name = "mysql"

    def __init__(self) -> None:
        self.database = _env("MYSQL_DATABASE", "MYSQLDATABASE", default="netmon")
        self.config: Dict[str, Any] = {
            "host": _env("MYSQL_HOST", "MYSQLHOST", default="127.0.0.1"),
            "port": _env_int("MYSQL_PORT", _env_int("MYSQLPORT", 3306)),
            "user": _env("MYSQL_USER", "MYSQLUSER", default="root"),
            "password": _env("MYSQL_PASSWORD", "MYSQLPASSWORD", default=""),
            "connection_timeout": _env_int("MYSQL_CONNECT_TIMEOUT", 10),
        }
        ssl_ca = _env("MYSQL_SSL_CA")
        if ssl_ca:
            self.config["ssl_ca"] = ssl_ca
        if _env_bool("MYSQL_SSL_DISABLED", False):
            self.config["ssl_disabled"] = True
        self._pool = None

    def init(self) -> None:
        import mysql.connector  # imported lazily: only needed when this backend is chosen
        from mysql.connector import pooling

        # The database name is interpolated into DDL (identifiers cannot be bound
        # as parameters), so restrict it to a safe character set.
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", self.database or ""):
            raise DatabaseError("MYSQL_DATABASE may only contain letters, digits and underscores.")

        self._create_database_if_missing(mysql.connector)

        self._pool = pooling.MySQLConnectionPool(
            pool_name="netmon_pool",
            pool_size=max(1, min(_env_int("MYSQL_POOL_SIZE", 5), 32)),
            pool_reset_session=True,
            database=self.database,
            **self.config,
        )

        conn = self._pool.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    scanned_at       DATETIME(3)  NOT NULL,
                    host_name        VARCHAR(120) NOT NULL,
                    ip_address       VARCHAR(255) NOT NULL,
                    target_type      VARCHAR(10)  NOT NULL,
                    status           VARCHAR(10)  NOT NULL,
                    response_time_ms DOUBLE       NULL,
                    INDEX idx_scanned_at (scanned_at),
                    INDEX idx_host_name (host_name, scanned_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()  # returns the connection to the pool

    def _create_database_if_missing(self, connector) -> None:
        """Create the schema when the account is allowed to; otherwise assume it exists.

        Managed MySQL services (Railway, Aiven, PlanetScale-style) usually pre-create
        the database and may not grant CREATE DATABASE, so a failure is not fatal.
        """
        try:
            conn = connector.connect(**self.config)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{self.database}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
                conn.commit()
                cursor.close()
            finally:
                conn.close()
        except connector.Error as exc:
            logger.warning(
                "Could not auto-create MySQL database '%s' (%s). Assuming it already exists.",
                self.database,
                exc,
            )

    def _get_connection(self):
        if self._pool is None:
            raise DatabaseError("MySQL pool is not initialised.")
        return self._pool.get_connection()

    def insert_many(self, records: List[Record]) -> int:
        rows = [
            (
                _as_utc(r["scanned_at"]).replace(tzinfo=None),  # DATETIME stores naive UTC
                r["host_name"],
                r["ip_address"],
                r["target_type"],
                r["status"],
                r["response_time_ms"],
            )
            for r in records
        ]
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.executemany(
                f"""INSERT INTO {TABLE_NAME}
                    (scanned_at, host_name, ip_address, target_type, status, response_time_ms)
                    VALUES (%s, %s, %s, %s, %s, %s)""",
                rows,
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()
        return len(rows)

    def fetch(self, limit: int, host: Optional[str], status: Optional[str]) -> List[Record]:
        clauses: List[str] = []
        params: List[Any] = []
        if host:
            clauses.append("host_name = %s")
            params.append(host)
        if status:
            clauses.append("status = %s")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT id, scanned_at, host_name, ip_address, target_type, status, response_time_ms "
            f"FROM {TABLE_NAME}{where} ORDER BY scanned_at DESC, id ASC LIMIT %s"
        )
        params.append(limit)

        conn = self._get_connection()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            cursor.close()
        finally:
            conn.close()

        for row in rows:
            row["scanned_at"] = _iso(row["scanned_at"])
        return rows

    def purge_older_than(self, cutoff: datetime) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"DELETE FROM {TABLE_NAME} WHERE scanned_at < %s",
                (_as_utc(cutoff).replace(tzinfo=None),),
            )
            removed = cursor.rowcount
            conn.commit()
            cursor.close()
        finally:
            conn.close()
        return removed


# --------------------------------------------------------------------------- #
# MongoDB backend
# --------------------------------------------------------------------------- #
class MongoBackend(BaseBackend):
    name = "mongodb"

    def __init__(self) -> None:
        self.uri = _env("MONGODB_URI", "MONGO_URL", default="mongodb://localhost:27017")
        self.database = _env("MONGODB_DB", default="netmon")
        self.timeout_ms = _env_int("MONGODB_TIMEOUT_MS", 5000)
        self._client = None
        self._collection = None

    def init(self) -> None:
        from pymongo import ASCENDING, DESCENDING, MongoClient  # lazy import

        self._client = MongoClient(
            self.uri,
            serverSelectionTimeoutMS=self.timeout_ms,
            connectTimeoutMS=self.timeout_ms,
            tz_aware=True,
            tzinfo=timezone.utc,
        )
        # Fail fast with a clear error if the server is unreachable or credentials are wrong.
        self._client.admin.command("ping")

        self._collection = self._client[self.database][TABLE_NAME]
        self._collection.create_index([("scanned_at", DESCENDING)], name="idx_scanned_at")
        self._collection.create_index(
            [("host_name", ASCENDING), ("scanned_at", DESCENDING)], name="idx_host_scanned_at"
        )

    def _col(self):
        if self._collection is None:
            raise DatabaseError("MongoDB collection is not initialised.")
        return self._collection

    def insert_many(self, records: List[Record]) -> int:
        documents = [
            {
                "scanned_at": _as_utc(r["scanned_at"]),
                "host_name": r["host_name"],
                "ip_address": r["ip_address"],
                "target_type": r["target_type"],
                "status": r["status"],
                "response_time_ms": r["response_time_ms"],
            }
            for r in records
        ]
        result = self._col().insert_many(documents, ordered=False)
        return len(result.inserted_ids)

    def fetch(self, limit: int, host: Optional[str], status: Optional[str]) -> List[Record]:
        query: Dict[str, Any] = {}
        if host:
            query["host_name"] = host
        if status:
            query["status"] = status
        cursor = self._col().find(query).sort([("scanned_at", -1), ("_id", 1)]).limit(limit)

        results: List[Record] = []
        for doc in cursor:
            results.append(
                {
                    "id": str(doc["_id"]),
                    "scanned_at": _iso(doc["scanned_at"]),
                    "host_name": doc.get("host_name"),
                    "ip_address": doc.get("ip_address"),
                    "target_type": doc.get("target_type"),
                    "status": doc.get("status"),
                    "response_time_ms": doc.get("response_time_ms"),
                }
            )
        return results

    def purge_older_than(self, cutoff: datetime) -> int:
        result = self._col().delete_many({"scanned_at": {"$lt": _as_utc(cutoff)}})
        return result.deleted_count

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._collection = None


# --------------------------------------------------------------------------- #
# Backend registry and public helper functions
# --------------------------------------------------------------------------- #
_BACKENDS = {
    "sqlite": SQLiteBackend,
    "mysql": MySQLBackend,
    "mongodb": MongoBackend,
    "mongo": MongoBackend,  # convenient alias
}

_backend: Optional[BaseBackend] = None
_backend_lock = threading.RLock()


def get_backend_name() -> str:
    """Return the configured backend name (never raises)."""
    configured = (os.getenv("DB_BACKEND") or "sqlite").strip().lower()
    return "mongodb" if configured == "mongo" else configured


def init_db() -> BaseBackend:
    """Create the selected backend, build the schema/indexes and verify connectivity.

    Safe to call repeatedly; an already-initialised backend is reused.

    Raises:
        DatabaseError: unknown ``DB_BACKEND`` value, or the database is unreachable.
    """
    global _backend
    with _backend_lock:
        if _backend is not None:
            return _backend

        name = get_backend_name()
        backend_cls = _BACKENDS.get(name)
        if backend_cls is None:
            raise DatabaseError(
                f"Unsupported DB_BACKEND '{name}'. Choose one of: sqlite, mysql, mongodb."
            )

        backend = backend_cls()
        try:
            backend.init()
        except DatabaseError:
            raise
        except Exception as exc:  # driver-specific errors differ per engine
            raise DatabaseError(f"Could not initialise {name} backend: {exc}") from exc

        _backend = backend
        logger.info("Database backend ready: %s", name)
        return _backend


def _ready_backend() -> BaseBackend:
    """Return an initialised backend, retrying initialisation if an earlier attempt failed."""
    return _backend if _backend is not None else init_db()


def insert_logs(records: List[Record]) -> int:
    """Persist one scan worth of records.

    Returns:
        Number of rows written.

    Raises:
        DatabaseError: when the write fails for any reason.
    """
    if not records:
        return 0
    try:
        return _ready_backend().insert_many(records)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError(f"Failed to insert logs: {exc}") from exc


def fetch_logs(limit: int = 100, host: Optional[str] = None, status: Optional[str] = None) -> List[Record]:
    """Read historical records, newest scan first.

    Args:
        limit:  maximum number of rows to return.
        host:   optional exact host-name filter.
        status: optional "ONLINE" / "OFFLINE" filter.

    Raises:
        DatabaseError: when the read fails for any reason.
    """
    try:
        return _ready_backend().fetch(limit, host, status)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError(f"Failed to fetch logs: {exc}") from exc


def purge_old_logs(days: int) -> int:
    """Delete records older than ``days`` days (retention policy). Returns rows removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        return _ready_backend().purge_older_than(cutoff)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError(f"Failed to purge old logs: {exc}") from exc


def close_db() -> None:
    """Close open connections (call on application shutdown)."""
    global _backend
    with _backend_lock:
        if _backend is not None:
            try:
                _backend.close()
            finally:
                _backend = None
