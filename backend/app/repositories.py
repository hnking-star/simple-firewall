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
