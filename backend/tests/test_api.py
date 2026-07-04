import sqlite3
from unittest.mock import Mock

import pytest

from app import create_app


def table_columns(conn, table_name):
    """Return column names for a SQLite table."""
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [row['name'] for row in rows]


def test_health_endpoint_returns_ok(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_database_schema_matches_planned_tables(db_connection):
    rows = db_connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = [row['name'] for row in rows]
    assert 'rules' in names
    assert 'rule_updates' in names
    assert 'traffic_logs' in names
    assert 'system_logs' in names
    assert 'settings' in names

    assert table_columns(db_connection, 'rules') == [
        'id', 'name', 'action', 'direction', 'protocol', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 'enabled', 'priority', 'dsl_text',
        'created_at', 'updated_at'
    ]
    assert table_columns(db_connection, 'rule_updates') == [
        'id', 'rule_id', 'operation', 'status', 'message', 'created_at',
        'applied_at'
    ]
    assert table_columns(db_connection, 'traffic_logs') == [
        'id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'direction', 'action', 'rule_id', 'packet_len', 'reason'
    ]
    assert table_columns(db_connection, 'system_logs') == [
        'id', 'timestamp', 'level', 'module', 'message'
    ]
    assert table_columns(db_connection, 'settings') == [
        'key', 'value', 'description', 'updated_at'
    ]


def test_settings_defaults_include_descriptions(db_connection):
    rows = db_connection.execute(
        'SELECT key, value, description, updated_at FROM settings ORDER BY key'
    ).fetchall()
    settings = {row['key']: row for row in rows}

    assert set(settings) == {
        'interface', 'iptables_enabled', 'sniffer_enabled', 'update_mode',
        'update_interval', 'update_batch_size'
    }
    assert settings['interface']['value'] == 'any'
    assert settings['iptables_enabled']['value'] == '0'
    assert settings['sniffer_enabled']['value'] == '0'
    assert settings['update_mode']['value'] == 'immediate'
    assert settings['update_interval']['value'] == '30'
    assert settings['update_batch_size']['value'] == '3'
    assert all(row['description'] for row in rows)
    assert all(row['updated_at'] for row in rows)


def test_create_app_initializes_database(db_path):
    create_app({'DATABASE_PATH': str(db_path), 'TESTING': True})
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        assert table_columns(conn, 'rules') == [
            'id', 'name', 'action', 'direction', 'protocol', 'src_ip',
            'dst_ip', 'src_port', 'dst_port', 'enabled', 'priority',
            'dsl_text', 'created_at', 'updated_at'
        ]
    finally:
        conn.close()


def test_create_and_list_rule(client):
    payload = {
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
        'priority': 10,
    }
    create_response = client.post('/api/rules', json=payload)
    assert create_response.status_code == 201
    created = create_response.get_json()
    assert created['name'] == 'block dns'
    assert created['action'] == 'DENY'

    list_response = client.get('/api/rules')
    assert list_response.status_code == 200
    rules = list_response.get_json()['items']
    assert len(rules) == 1
    assert rules[0]['dst_ip'] == '8.8.8.8'


def test_parse_rule_endpoint(client):
    response = client.post('/api/rules/parse', json={
        'dsl_text': 'ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22'
    })
    assert response.status_code == 200
    assert response.get_json()['dst_port'] == '22'


def assert_json_error(response):
    """Assert that an API response is a JSON 400 error."""
    assert response.status_code == 400
    assert 'error' in response.get_json()


def test_create_rule_rejects_missing_or_empty_dsl_text(client):
    for dsl_text in (None, ''):
        response = client.post('/api/rules', json={
            'name': 'bad rule',
            'dsl_text': dsl_text,
        })
        assert response.status_code == 400
        assert response.get_json() == {
            'error': 'dsl_text must be a non-empty string'
        }


def test_parse_rule_rejects_missing_or_empty_dsl_text(client):
    for dsl_text in (None, ''):
        response = client.post('/api/rules/parse', json={'dsl_text': dsl_text})
        assert response.status_code == 400
        assert response.get_json() == {
            'error': 'dsl_text must be a non-empty string'
        }


def test_rule_endpoints_reject_invalid_dsl(client):
    create_response = client.post('/api/rules', json={
        'name': 'bad rule',
        'dsl_text': 'BLOCK OUT UDP FROM ANY TO ANY',
    })
    parse_response = client.post('/api/rules/parse', json={
        'dsl_text': 'BLOCK OUT UDP FROM ANY TO ANY',
    })

    assert_json_error(create_response)
    assert_json_error(parse_response)


def test_stats_returns_expected_keys(client):
    response = client.get('/api/stats')

    assert response.status_code == 200
    assert set(response.get_json()) == {
        'blocked_count', 'allowed_count', 'active_connections', 'enabled_rules'
    }


def test_settings_can_be_read_and_updated(client):
    get_response = client.get('/api/settings')
    assert get_response.status_code == 200
    assert get_response.get_json()['interface'] == 'any'

    put_response = client.put('/api/settings', json={
        'interface': 'eth0',
        'update_batch_size': '5',
        'missing': 'ignored',
    })

    assert put_response.status_code == 200
    settings = put_response.get_json()
    assert settings['interface'] == 'eth0'
    assert settings['update_batch_size'] == '5'
    assert 'missing' not in settings


def test_logs_returns_empty_items_initially(client):
    response = client.get('/api/logs')

    assert response.status_code == 200
    assert response.get_json() == {'items': []}


def test_apply_enabled_rules_returns_dry_run_commands(client):
    client.post('/api/rules', json={
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
    })

    response = client.post('/api/rules/apply', json={'dry_run': True})

    assert response.status_code == 200
    body = response.get_json()
    assert body['applied_count'] == 1
    assert body['results'][0]['command'] == [
        'iptables', '-A', 'OUTPUT', '-p', 'udp', '-d', '8.8.8.8',
        '--dport', '53', '-j', 'DROP'
    ]


def test_sniffer_start_and_stop(client, monkeypatch):
    monkeypatch.setattr('app.sniffer_service.sniff', lambda **kwargs: None)
    start_response = client.post('/api/sniffer/start')
    stop_response = client.post('/api/sniffer/stop')

    assert start_response.status_code == 200
    assert start_response.get_json() == {'running': True}
    assert stop_response.status_code == 200
    assert stop_response.get_json() == {'running': False}


def test_recent_traffic_returns_log_items(client):
    response = client.get('/api/traffic/recent')

    assert response.status_code == 200
    assert response.get_json() == {'items': []}


@pytest.mark.parametrize('body', ['[]', 'null', '"text"', '1', 'true'])
def test_object_body_endpoints_reject_non_object_json(client, body):
    endpoints = [
        ('post', '/api/rules'),
        ('post', '/api/rules/parse'),
        ('put', '/api/settings'),
        ('post', '/api/rules/apply'),
    ]

    for method, path in endpoints:
        response = getattr(client, method)(
            path, data=body, content_type='application/json'
        )

        assert response.status_code == 400
        assert response.get_json() == {
            'error': 'request body must be a JSON object'
        }


def test_apply_rules_defaults_to_dry_run_without_body(client, monkeypatch):
    run = Mock()
    monkeypatch.setattr('app.iptables_adapter.subprocess.run', run)
    client.post('/api/rules', json={
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
    })

    no_body_response = client.post('/api/rules/apply')
    empty_body_response = client.post('/api/rules/apply', json={})

    assert no_body_response.status_code == 200
    assert empty_body_response.status_code == 200
    run.assert_not_called()


def test_update_and_delete_rule_api(client):
    created = client.post('/api/rules', json={
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
        'priority': 10,
    }).get_json()

    update_response = client.put(f"/api/rules/{created['id']}", json={
        'name': 'allow ssh',
        'dsl_text': 'ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22',
        'enabled': False,
        'priority': 5,
    })

    assert update_response.status_code == 200
    updated = update_response.get_json()
    assert updated['name'] == 'allow ssh'
    assert updated['action'] == 'ALLOW'
    assert updated['direction'] == 'IN'
    assert updated['protocol'] == 'TCP'
    assert updated['dst_port'] == '22'
    assert updated['enabled'] is False
    assert updated['priority'] == 5

    delete_response = client.delete(f"/api/rules/{created['id']}")

    assert delete_response.status_code == 200
    deleted = delete_response.get_json()
    assert deleted['deleted'] is True
    assert deleted['id'] == created['id']
    assert client.get('/api/rules').get_json() == {'items': []}


def test_rule_updates_are_created_and_marked_applied(client, db_connection):
    client.put('/api/settings', json={'update_mode': 'timed'})
    create_response = client.post('/api/rules', json={
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
    })
    rule_id = create_response.get_json()['id']
    client.put(f'/api/rules/{rule_id}', json={
        'name': 'block web',
        'dsl_text': 'DENY OUT TCP FROM ANY TO 1.1.1.1 SPORT ANY DPORT 443',
    })
    client.delete(f'/api/rules/{rule_id}')

    pending = db_connection.execute(
        "SELECT operation, status FROM rule_updates ORDER BY id"
    ).fetchall()
    assert [(row['operation'], row['status']) for row in pending] == [
        ('CREATE', 'PENDING'), ('UPDATE', 'PENDING'), ('DELETE', 'PENDING')
    ]

    apply_response = client.post('/api/rules/apply', json={'dry_run': True})

    assert apply_response.status_code == 200
    applied = db_connection.execute(
        "SELECT status, message, applied_at FROM rule_updates ORDER BY id"
    ).fetchall()
    assert [row['status'] for row in applied] == ['APPLIED', 'APPLIED', 'APPLIED']
    assert all('dry-run' in row['message'] for row in applied)
    assert all(row['applied_at'] for row in applied)


def test_counted_mode_applies_when_pending_reaches_threshold(client, db_connection):
    client.put('/api/settings', json={
        'update_mode': 'counted',
        'update_batch_size': '2',
    })

    first = client.post('/api/rules', json={
        'name': 'rule one',
        'dsl_text': 'ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22',
    })
    second = client.post('/api/rules', json={
        'name': 'rule two',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
    })

    assert first.status_code == 201
    assert 'apply_result' not in first.get_json()
    assert second.status_code == 201
    assert second.get_json()['apply_result']['applied_count'] == 2
    rows = db_connection.execute('SELECT status FROM rule_updates ORDER BY id').fetchall()
    assert [row['status'] for row in rows] == ['APPLIED', 'APPLIED']


def test_real_apply_requires_enabled_setting_and_confirmation(client, monkeypatch):
    run = Mock()
    monkeypatch.setattr('app.iptables_adapter.subprocess.run', run)
    client.post('/api/rules', json={
        'name': 'allow ssh',
        'dsl_text': 'ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22',
    })

    missing_confirm = client.post('/api/rules/apply', json={'dry_run': False})
    disabled = client.post('/api/rules/apply', json={
        'dry_run': False,
        'confirm_apply': 'APPLY_IPTABLES',
    })

    assert missing_confirm.status_code == 400
    assert disabled.status_code == 400
    run.assert_not_called()
