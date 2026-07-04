def test_health_endpoint_returns_ok(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_database_schema_contains_rules_table(db_connection):
    rows = db_connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = [row['name'] for row in rows]
    assert 'rules' in names
    assert 'traffic_logs' in names
    assert 'system_logs' in names
