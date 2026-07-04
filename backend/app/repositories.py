from .db import connect_db

RULE_COLUMNS = [
    'id', 'name', 'action', 'direction', 'protocol', 'src_ip', 'dst_ip',
    'src_port', 'dst_port', 'enabled', 'priority', 'dsl_text', 'created_at',
    'updated_at',
]


def row_to_dict(row):
    """Convert a SQLite rule row into an API dictionary."""
    if row is None:
        return None
    data = {key: row[key] for key in row.keys()}
    if 'enabled' in data:
        data['enabled'] = bool(data['enabled'])
    return data


def create_rule(database_path, rule, name, enabled=True, priority=100, dsl_text=''):
    """Persist a parsed firewall rule and return the stored row."""
    conn = connect_db(database_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO rules (
                name, action, direction, protocol, src_ip, dst_ip, src_port,
                dst_port, enabled, priority, dsl_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                rule.action,
                rule.direction,
                rule.protocol,
                rule.src_ip,
                rule.dst_ip,
                rule.src_port,
                rule.dst_port,
                1 if enabled else 0,
                priority,
                dsl_text,
            ),
        )
        conn.commit()
        row = conn.execute(
            f"SELECT {', '.join(RULE_COLUMNS)} FROM rules WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        return row_to_dict(row)
    finally:
        conn.close()


def get_rule(database_path, rule_id):
    """Return one rule by id, or None when it does not exist."""
    conn = connect_db(database_path)
    try:
        row = conn.execute(
            f"SELECT {', '.join(RULE_COLUMNS)} FROM rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        return row_to_dict(row)
    finally:
        conn.close()


def list_rules(database_path):
    """Return all rules ordered by priority and id."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute(
            f"SELECT {', '.join(RULE_COLUMNS)} FROM rules ORDER BY priority, id"
        ).fetchall()
        return [row_to_dict(row) for row in rows]
    finally:
        conn.close()


def row_to_plain_dict(row):
    """Convert any SQLite row to a plain dictionary."""
    return {key: row[key] for key in row.keys()}


def get_settings(database_path):
    """Return all persisted settings as key-value strings."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        return {row['key']: row['value'] for row in rows}
    finally:
        conn.close()


def update_settings(database_path, values):
    """Update existing setting keys and return all settings."""
    conn = connect_db(database_path)
    try:
        existing = {
            row['key'] for row in conn.execute('SELECT key FROM settings').fetchall()
        }
        for key, value in values.items():
            if key in existing:
                conn.execute(
                    """
                    UPDATE settings
                    SET value = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE key = ?
                    """,
                    (str(value), key),
                )
        conn.commit()
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        return {row['key']: row['value'] for row in rows}
    finally:
        conn.close()


def list_logs(database_path):
    """Return traffic log rows ordered newest first."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute(
            'SELECT * FROM traffic_logs ORDER BY timestamp DESC, id DESC'
        ).fetchall()
        return [row_to_plain_dict(row) for row in rows]
    finally:
        conn.close()


def get_stats(database_path):
    """Return aggregate firewall counters for the API."""
    conn = connect_db(database_path)
    try:
        blocked_count = conn.execute(
            "SELECT COUNT(*) AS count FROM traffic_logs WHERE action IN ('DENY', 'DROP')"
        ).fetchone()['count']
        allowed_count = conn.execute(
            "SELECT COUNT(*) AS count FROM traffic_logs WHERE action IN ('ALLOW', 'ACCEPT')"
        ).fetchone()['count']
        enabled_rules = conn.execute(
            'SELECT COUNT(*) AS count FROM rules WHERE enabled = 1'
        ).fetchone()['count']
        return {
            'blocked_count': blocked_count,
            'allowed_count': allowed_count,
            'active_connections': 0,
            'enabled_rules': enabled_rules,
        }
    finally:
        conn.close()


def list_enabled_rules(database_path):
    """Return enabled rules ordered by priority and id."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute(
            f"""
            SELECT {', '.join(RULE_COLUMNS)} FROM rules
            WHERE enabled = 1
            ORDER BY priority, id
            """
        ).fetchall()
        return [row_to_dict(row) for row in rows]
    finally:
        conn.close()
