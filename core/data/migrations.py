"""
MURNET DB MIGRATIONS v6.0
Versioned schema migrations with rollback support.
"""

import sqlite3
import logging
from typing import List, Optional, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Migration registry
# Each migration: (version, description, up_sql, down_sql)
# down_sql can be None if rollback is not possible (e.g. column drops).
# ---------------------------------------------------------------------------

MIGRATIONS: List[dict] = [
    {
        "version": 1,
        "description": "Initial schema (identity, messages, dht_data, routing, peers, metadata)",
        "up": """
            CREATE TABLE IF NOT EXISTS identity (
                id INTEGER PRIMARY KEY,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                address TEXT UNIQUE NOT NULL,
                created_at REAL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                from_addr TEXT NOT NULL,
                to_addr TEXT NOT NULL,
                content BLOB,
                content_preview TEXT,
                timestamp REAL NOT NULL,
                delivered INTEGER DEFAULT 0,
                read INTEGER DEFAULT 0,
                signature TEXT,
                ttl INTEGER,
                expires_at REAL,
                compressed INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_messages_to
                ON messages(to_addr);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp
                ON messages(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_expires
                ON messages(expires_at) WHERE expires_at IS NOT NULL;

            CREATE TABLE IF NOT EXISTS dht_data (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                value_type TEXT DEFAULT 'binary',
                version INTEGER DEFAULT 1,
                timestamp REAL DEFAULT (strftime('%s','now')),
                ttl INTEGER,
                expires_at REAL,
                replicas TEXT,
                owner TEXT
            );

            CREATE TABLE IF NOT EXISTS routing (
                destination TEXT PRIMARY KEY,
                next_hop TEXT NOT NULL,
                cost REAL DEFAULT 1.0,
                latency_ms INTEGER,
                last_seen REAL DEFAULT (strftime('%s','now')),
                hop_count INTEGER DEFAULT 1,
                stable INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS peers (
                address TEXT PRIMARY KEY,
                ip TEXT,
                port INTEGER,
                public_key BLOB,
                last_seen REAL DEFAULT (strftime('%s','now')),
                trust_score REAL DEFAULT 0.5,
                failed_attempts INTEGER DEFAULT 0,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at REAL DEFAULT (strftime('%s','now'))
            );
        """,
        "down": None,  # Cannot drop initial schema safely
    },
    {
        "version": 2,
        "description": "Add message_type column to messages",
        "up": """
            ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text';
        """,
        "down": None,  # SQLite does not support DROP COLUMN before 3.35
    },
    {
        "version": 3,
        "description": "Add name_bindings table for Name Service",
        "up": """
            CREATE TABLE IF NOT EXISTS name_bindings (
                name TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                public_key BLOB NOT NULL,
                signature TEXT NOT NULL,
                registered_at REAL DEFAULT (strftime('%s','now')),
                expires_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_name_bindings_address
                ON name_bindings(address);
        """,
        "down": """
            DROP TABLE IF EXISTS name_bindings;
        """,
    },
    {
        "version": 4,
        "description": "Add sessions table for tracking active sessions",
        "up": """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                peer_address TEXT NOT NULL,
                session_key BLOB,
                created_at REAL DEFAULT (strftime('%s','now')),
                last_active REAL DEFAULT (strftime('%s','now')),
                expires_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_peer
                ON sessions(peer_address);
        """,
        "down": """
            DROP TABLE IF EXISTS sessions;
        """,
    },
    {
        "version": 5,
        "description": "Add files table for stored file metadata",
        "up": """
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime_type TEXT,
                hash TEXT NOT NULL,
                owner_addr TEXT NOT NULL,
                stored_at REAL DEFAULT (strftime('%s','now')),
                expires_at REAL,
                path TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_files_owner
                ON files(owner_addr);
        """,
        "down": """
            DROP TABLE IF EXISTS files;
        """,
    },
    {
        "version": 6,
        "description": "Add trust_events table for audit log",
        "up": """
            CREATE TABLE IF NOT EXISTS trust_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                delta REAL DEFAULT 0.0,
                reason TEXT,
                timestamp REAL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_trust_events_peer
                ON trust_events(peer_address);
        """,
        "down": """
            DROP TABLE IF EXISTS trust_events;
        """,
    },
]


class MigrationError(Exception):
    pass


def _ensure_schema_version_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            description TEXT,
            applied_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    conn.commit()


def get_current_version(conn: sqlite3.Connection) -> int:
    _ensure_schema_version_table(conn)
    row = conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()
    return row[0] if row[0] is not None else 0


def get_applied_versions(conn: sqlite3.Connection) -> List[int]:
    _ensure_schema_version_table(conn)
    rows = conn.execute(
        "SELECT version FROM schema_version ORDER BY version"
    ).fetchall()
    return [r[0] for r in rows]


def migrate(conn: sqlite3.Connection, target_version: Optional[int] = None) -> int:
    """
    Apply all pending migrations up to target_version.
    Returns the new version number.

    Args:
        conn: SQLite connection (must NOT be in autocommit mode for safety).
        target_version: Migrate up to this version. Defaults to latest.

    Raises:
        MigrationError: If a migration fails.
    """
    if target_version is None:
        target_version = MIGRATIONS[-1]["version"] if MIGRATIONS else 0

    current = get_current_version(conn)

    if current == target_version:
        logger.debug("Database already at version %d, nothing to do.", current)
        return current

    if current > target_version:
        raise MigrationError(
            f"Downgrade requested (current={current}, target={target_version}). "
            "Use rollback() explicitly."
        )

    applied = get_applied_versions(conn)
    pending = [m for m in MIGRATIONS
               if m["version"] > current and m["version"] <= target_version]

    for migration in pending:
        ver = migration["version"]
        desc = migration["description"]
        logger.info("Applying migration %d: %s", ver, desc)

        try:
            # Execute each statement separately (SQLite executescript commits
            # automatically, so we use manual transaction handling here)
            statements = [
                s.strip() for s in migration["up"].split(";")
                if s.strip()
            ]
            with conn:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version, description) VALUES (?, ?)",
                    (ver, desc)
                )
        except Exception as exc:
            raise MigrationError(
                f"Migration {ver} ('{desc}') failed: {exc}"
            ) from exc

    new_version = get_current_version(conn)
    logger.info("Migration complete. Version: %d → %d", current, new_version)
    return new_version


def rollback(conn: sqlite3.Connection, target_version: int) -> int:
    """
    Roll back migrations down to target_version.
    Only migrations with a 'down' script can be rolled back.

    Returns the new version number.
    """
    current = get_current_version(conn)

    if current <= target_version:
        logger.debug("Nothing to roll back (current=%d, target=%d).", current, target_version)
        return current

    to_rollback = [
        m for m in reversed(MIGRATIONS)
        if m["version"] > target_version and m["version"] <= current
    ]

    for migration in to_rollback:
        ver = migration["version"]
        desc = migration["description"]

        if migration["down"] is None:
            raise MigrationError(
                f"Migration {ver} ('{desc}') has no rollback script."
            )

        logger.info("Rolling back migration %d: %s", ver, desc)

        try:
            statements = [
                s.strip() for s in migration["down"].split(";")
                if s.strip()
            ]
            with conn:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "DELETE FROM schema_version WHERE version = ?", (ver,)
                )
        except Exception as exc:
            raise MigrationError(
                f"Rollback of migration {ver} failed: {exc}"
            ) from exc

    new_version = get_current_version(conn)
    logger.info("Rollback complete. Version: %d → %d", current, new_version)
    return new_version


def status(conn: sqlite3.Connection) -> dict:
    """Return current migration status."""
    current = get_current_version(conn)
    latest = MIGRATIONS[-1]["version"] if MIGRATIONS else 0
    applied = get_applied_versions(conn)
    pending = [m["version"] for m in MIGRATIONS if m["version"] not in applied]

    return {
        "current_version": current,
        "latest_version": latest,
        "is_up_to_date": current == latest,
        "applied": applied,
        "pending": pending,
    }
