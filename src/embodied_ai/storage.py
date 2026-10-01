"""统计分析准入服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 3

USER_ROLES = ("operator", "statistician", "approver", "auditor", "admin")

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_catalog (
    protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor', 'admin')),
    role_version INTEGER NOT NULL DEFAULT 1 CHECK (role_version > 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_assignments (
    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('bootstrap', 'created', 'role_changed', 'deactivated')),
    role TEXT,
    role_version INTEGER,
    granted_by TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_user
ON role_assignments(user_id, sequence_id);

CREATE TABLE IF NOT EXISTS robots (
    robot_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (robot_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (protocol_id, protocol_version) REFERENCES protocol_catalog(protocol_id, version)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    stratum_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
ON exclusion_requests(observation_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_denials (
    denial_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    code TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_denials_time
ON access_denials(denial_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "protocol_catalog", "users", "role_assignments", "robots", "builds",
    "batches", "observations", "idempotency_keys", "exclusion_requests", "analysis_jobs",
    "analyses", "decisions", "audit_events", "access_denials",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    # 服务由 ThreadingHTTPServer 每请求一线程驱动；所有写操作都走 BEGIN IMMEDIATE
    # 显式事务并配合 busy_timeout，因此允许同一连接跨线程串行使用。
    connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _migrate_users(connection: sqlite3.Connection) -> None:
    """把旧版 users 表升级为带授权追踪且包含 admin 角色的结构。

    SQLite 的 ADD COLUMN 无法放宽已有 CHECK 约束，因此按官方 12 步表重建流程：
    外键检查须在事务外关闭、重建在单事务内完成，历史账号与业务外键原样保留。
    """

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
    if {"role_version", "created_by", "updated_at"} <= columns:
        return
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    has_created_at = "created_at" in columns
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        with transaction(connection, immediate=True):
            connection.execute("ALTER TABLE users RENAME TO users_legacy_tmp")
            connection.execute("""
                CREATE TABLE users (
                    user_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor', 'admin')),
                    role_version INTEGER NOT NULL DEFAULT 1 CHECK (role_version > 0),
                    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )""")
            created_at_expr = "created_at" if has_created_at else "?"
            connection.execute(
                f"""
                INSERT INTO users(user_id,display_name,role,role_version,active,created_by,created_at,updated_at)
                SELECT user_id, display_name, role, 1, active, NULL, {created_at_expr}, {created_at_expr}
                FROM users_legacy_tmp""",
                () if has_created_at else (stamp, stamp),
            )
            connection.execute("DROP TABLE users_legacy_tmp")
            violations = connection.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError(f"用户表迁移发现外键悬挂: {violations!r}")
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    _migrate_users(connection)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
