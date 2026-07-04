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
    conn = connect_db(database_path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                action TEXT NOT NULL,
                direction TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'any',
                src_ip TEXT,
                dst_ip TEXT,
                src_port TEXT,
                dst_port TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                dsl_text TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rule_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                operation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                applied_at TEXT,
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                direction TEXT,
                action TEXT,
                rule_id INTEGER,
                packet_len INTEGER,
                reason TEXT,
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL,
                module TEXT,
                message TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO settings (key, value, description)
            VALUES (?, ?, ?)
            """,
            [
                ('interface', DEFAULT_INTERFACE, 'Network interface to monitor'),
                ('iptables_enabled', '0', 'Whether iptables enforcement is enabled'),
                ('sniffer_enabled', '0', 'Whether packet sniffing is enabled'),
                ('update_mode', DEFAULT_UPDATE_MODE, 'Rule update application mode'),
                ('update_interval', str(DEFAULT_UPDATE_INTERVAL), 'Rule update interval in seconds'),
                ('update_batch_size', str(DEFAULT_UPDATE_BATCH_SIZE), 'Rule update batch size'),
            ],
        )
        conn.commit()
    finally:
        conn.close()
