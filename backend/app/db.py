import sqlite3

from .config import (
    DEFAULT_INTERFACE,
    DEFAULT_UPDATE_BATCH_SIZE,
    DEFAULT_UPDATE_INTERVAL,
    DEFAULT_UPDATE_MODE,
)


def connect_db(database_path):
    """Open a SQLite connection with row access by name."""
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(database_path):
    """Create the firewall schema and seed default settings."""
    with connect_db(database_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                action TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'any',
                source_ip TEXT,
                source_port TEXT,
                destination_ip TEXT,
                destination_port TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rule_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                operation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                applied_at TEXT,
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                action TEXT,
                packet_size INTEGER
            );

            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        conn.executemany(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            [
                ('interface', DEFAULT_INTERFACE),
                ('iptables_enabled', '0'),
                ('sniffer_enabled', '0'),
                ('update_mode', DEFAULT_UPDATE_MODE),
                ('update_interval', str(DEFAULT_UPDATE_INTERVAL)),
                ('update_batch_size', str(DEFAULT_UPDATE_BATCH_SIZE)),
            ],
        )
