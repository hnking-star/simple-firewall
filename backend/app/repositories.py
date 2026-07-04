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


def row_to_plain_dict(row):
    """Convert any SQLite row to a plain dictionary."""
    return {key: row[key] for key in row.keys()}


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


def update_rule(database_path, rule_id, rule, name, enabled=True, priority=100, dsl_text=''):
    """Update a stored rule and return it, or None when missing."""
    conn = connect_db(database_path)
    try:
        cursor = conn.execute(
            """
            UPDATE rules
            SET name = ?, action = ?, direction = ?, protocol = ?, src_ip = ?,
                dst_ip = ?, src_port = ?, dst_port = ?, enabled = ?,
                priority = ?, dsl_text = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
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
                rule_id,
            ),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return None
        row = conn.execute(
            f"SELECT {', '.join(RULE_COLUMNS)} FROM rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        return row_to_dict(row)
    finally:
        conn.close()


def delete_rule(database_path, rule_id):
    """Delete one rule and return whether a row was removed."""
    conn = connect_db(database_path)
    try:
        cursor = conn.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        conn.commit()
        return cursor.rowcount > 0
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


def add_rule_update(database_path, rule_id, operation, status='PENDING', message=None):
    """Queue a rule update operation."""
    conn = connect_db(database_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO rule_updates (rule_id, operation, status, message)
            VALUES (?, ?, ?, ?)
            """,
            (rule_id, operation, status, message),
        )
        conn.commit()
        row = conn.execute(
            'SELECT * FROM rule_updates WHERE id = ?', (cursor.lastrowid,)
        ).fetchone()
        return row_to_plain_dict(row)
    finally:
        conn.close()


def list_pending_rule_updates(database_path):
    """Return pending rule update rows ordered by id."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute(
            "SELECT * FROM rule_updates WHERE status = 'PENDING' ORDER BY id"
        ).fetchall()
        return [row_to_plain_dict(row) for row in rows]
    finally:
        conn.close()


def mark_rule_updates(database_path, update_ids, status, message=None):
    """Mark queued rule updates with a new status and message."""
    if not update_ids:
        return 0
    conn = connect_db(database_path)
    try:
        placeholders = ','.join('?' for _ in update_ids)
        cursor = conn.execute(
            f"""
            UPDATE rule_updates
            SET status = ?, message = ?, applied_at = CURRENT_TIMESTAMP
            WHERE id IN ({placeholders})
            """,
            [status, message, *update_ids],
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_settings(database_path):
    """Return all persisted settings as key-value strings."""
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        return {row['key']: row['value'] for row in rows}
    finally:
        conn.close()


def _setting_value(value):
    """Normalize setting values before storing them."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


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
                    (_setting_value(value), key),
                )
        conn.commit()
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        return {row['key']: row['value'] for row in rows}
    finally:
        conn.close()


def list_logs(database_path, limit=None, exclude_ssh=False):
    """Return traffic log rows ordered newest first."""
    conn = connect_db(database_path)
    try:
        query = 'SELECT * FROM traffic_logs'
        params = []
        if exclude_ssh:
            query += ' WHERE src_port != ? AND dst_port != ?'
            params.extend(['22', '22'])
        query += ' ORDER BY timestamp DESC, id DESC'
        if limit is not None:
            query += ' LIMIT ?'
            params.append(int(limit))
        rows = conn.execute(query, params).fetchall()
        return [row_to_plain_dict(row) for row in rows]
    finally:
        conn.close()


def insert_traffic_log(database_path, record):
    """Insert one traffic log record and return the stored row."""
    conn = connect_db(database_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO traffic_logs (
                src_ip, dst_ip, src_port, dst_port, protocol, direction,
                action, rule_id, packet_len, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get('src_ip'),
                record.get('dst_ip'),
                record.get('src_port'),
                record.get('dst_port'),
                record.get('protocol'),
                record.get('direction'),
                record.get('action'),
                record.get('rule_id'),
                record.get('packet_len'),
                record.get('reason'),
            ),
        )
        conn.commit()
        row = conn.execute(
            'SELECT * FROM traffic_logs WHERE id = ?', (cursor.lastrowid,)
        ).fetchone()
        return row_to_plain_dict(row)
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


def match_packet_rule(database_path, record):
    """Return the first enabled DENY rule matching a packet record."""
    for rule in list_enabled_rules(database_path):
        if rule['action'] != 'DENY':
            continue
        if not _field_matches(rule['direction'], record.get('direction')):
            continue
        if not _field_matches(rule['protocol'], record.get('protocol')):
            continue
        if not _ip_matches(rule['src_ip'], record.get('src_ip')):
            continue
        if not _ip_matches(rule['dst_ip'], record.get('dst_ip')):
            continue
        if not _port_matches(rule['src_port'], record.get('src_port')):
            continue
        if not _port_matches(rule['dst_port'], record.get('dst_port')):
            continue
        return rule
    return None


def _field_matches(rule_value, packet_value):
    return rule_value == 'ANY' or str(rule_value).upper() == str(packet_value).upper()


def _ip_matches(rule_value, packet_value):
    if rule_value == 'ANY':
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(packet_value) in ipaddress.ip_network(rule_value, strict=False)
    except ValueError:
        return False


def _port_matches(rule_value, packet_value):
    if rule_value == 'ANY':
        return True
    try:
        port = int(packet_value)
    except (TypeError, ValueError):
        return False
    if '-' in str(rule_value):
        start, _, end = str(rule_value).partition('-')
        return int(start) <= port <= int(end)
    return str(port) == str(rule_value)
