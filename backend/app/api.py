from flask import Blueprint, current_app, jsonify, request

from .repositories import (
    add_rule_update,
    create_rule,
    delete_rule,
    get_settings,
    get_stats,
    list_logs,
    list_pending_rule_updates,
    list_rules,
    update_rule,
    update_settings,
)
from .rule_parser import RuleParser, RuleParserError
from .sniffer_service import SnifferService
from .update_service import RuleUpdateService

api = Blueprint('api', __name__, url_prefix='/api')
sniffer_service = SnifferService()


def _database_path():
    """Return the configured SQLite database path."""
    return current_app.config['DATABASE_PATH']


def _rule_to_dict(rule):
    """Convert a parsed firewall rule to a JSON-ready dict."""
    return {
        'action': rule.action,
        'direction': rule.direction,
        'protocol': rule.protocol,
        'src_ip': rule.src_ip,
        'dst_ip': rule.dst_ip,
        'src_port': rule.src_port,
        'dst_port': rule.dst_port,
    }


def _bad_request(message):
    """Return a JSON 400 error response."""
    return jsonify({'error': message}), 400


def _json_object():
    """Return request JSON as an object, or an error response."""
    if not request.get_data(cache=True):
        return {}, None
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _bad_request('request body must be a JSON object')
    return data, None


def _dsl_text(data):
    """Return valid DSL text or None when invalid."""
    value = data.get('dsl_text')
    if not isinstance(value, str) or not value:
        return None
    return value


def _maybe_apply_updates(database_path):
    """Apply pending updates when settings request automatic dry-run apply."""
    settings = get_settings(database_path)
    mode = settings.get('update_mode', 'immediate')
    if mode == 'immediate':
        return RuleUpdateService(database_path).apply_enabled_rules(dry_run=True)
    if mode == 'counted':
        batch_size = int(settings.get('update_batch_size', '3'))
        if len(list_pending_rule_updates(database_path)) >= batch_size:
            return RuleUpdateService(database_path).apply_enabled_rules(dry_run=True)
    return None


@api.get('/health')
def health():
    """Return service health status."""
    return jsonify({'status': 'ok'})


@api.get('/rules')
def rules_index():
    """List firewall rules."""
    return jsonify({'items': list_rules(_database_path())})


@api.post('/rules')
def rules_create():
    """Create a firewall rule from DSL text."""
    data, error = _json_object()
    if error:
        return error
    dsl_text = _dsl_text(data)
    if dsl_text is None:
        return _bad_request('dsl_text must be a non-empty string')
    name = data.get('name', '')
    if not name:
        return _bad_request('Missing name')
    try:
        rule = RuleParser.parse(dsl_text)
    except RuleParserError as exc:
        return _bad_request(str(exc))

    database_path = _database_path()
    created = create_rule(
        database_path,
        rule,
        name,
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100),
        dsl_text=dsl_text,
    )
    add_rule_update(database_path, created['id'], 'CREATE')
    apply_result = _maybe_apply_updates(database_path)
    if apply_result is not None:
        created['apply_result'] = apply_result
    return jsonify(created), 201


@api.put('/rules/<int:rule_id>')
def rules_update(rule_id):
    """Update a firewall rule from DSL text."""
    data, error = _json_object()
    if error:
        return error
    dsl_text = _dsl_text(data)
    if dsl_text is None:
        return _bad_request('dsl_text must be a non-empty string')
    name = data.get('name', '')
    if not name:
        return _bad_request('Missing name')
    try:
        rule = RuleParser.parse(dsl_text)
    except RuleParserError as exc:
        return _bad_request(str(exc))

    database_path = _database_path()
    updated = update_rule(
        database_path,
        rule_id,
        rule,
        name,
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100),
        dsl_text=dsl_text,
    )
    if updated is None:
        return jsonify({'error': 'rule not found'}), 404
    add_rule_update(database_path, rule_id, 'UPDATE')
    apply_result = _maybe_apply_updates(database_path)
    if apply_result is not None:
        updated['apply_result'] = apply_result
    return jsonify(updated)


@api.delete('/rules/<int:rule_id>')
def rules_delete(rule_id):
    """Delete a firewall rule."""
    database_path = _database_path()
    if not delete_rule(database_path, rule_id):
        return jsonify({'error': 'rule not found'}), 404
    add_rule_update(database_path, rule_id, 'DELETE')
    body = {'deleted': True, 'id': rule_id}
    apply_result = _maybe_apply_updates(database_path)
    if apply_result is not None:
        body['apply_result'] = apply_result
    return jsonify(body)


@api.post('/rules/parse')
def rules_parse():
    """Parse firewall rule DSL without storing it."""
    data, error = _json_object()
    if error:
        return error
    dsl_text = _dsl_text(data)
    if dsl_text is None:
        return _bad_request('dsl_text must be a non-empty string')
    try:
        rule = RuleParser.parse(dsl_text)
    except RuleParserError as exc:
        return _bad_request(str(exc))
    return jsonify(_rule_to_dict(rule))


@api.get('/stats')
def stats_show():
    """Return firewall runtime statistics."""
    return jsonify(get_stats(_database_path()))


@api.get('/logs')
def logs_index():
    """Return traffic logs."""
    return jsonify({'items': list_logs(_database_path())})


@api.get('/settings')
def settings_show():
    """Return persisted application settings."""
    return jsonify(get_settings(_database_path()))


@api.put('/settings')
def settings_update():
    """Update existing application settings."""
    data, error = _json_object()
    if error:
        return error
    if data.get('update_mode') not in (None, 'immediate', 'timed', 'counted'):
        return _bad_request('update_mode must be immediate, timed, or counted')
    return jsonify(update_settings(_database_path(), data))


@api.post('/sniffer/start')
def sniffer_start():
    """Start the packet sniffer service."""
    settings = get_settings(_database_path())
    return jsonify(sniffer_service.start(
        _database_path(),
        interface=settings.get('interface', 'any'),
    ))


@api.post('/sniffer/stop')
def sniffer_stop():
    """Stop the packet sniffer service."""
    return jsonify(sniffer_service.stop())


@api.post('/rules/apply')
def rules_apply():
    """Apply enabled rules through the update service."""
    data, error = _json_object()
    if error:
        return error
    dry_run = data.get('dry_run', True)
    database_path = _database_path()
    if dry_run is False:
        settings = get_settings(database_path)
        if (
            settings.get('iptables_enabled') != 'true'
            or data.get('confirm_apply') != 'APPLY_IPTABLES'
        ):
            return _bad_request('real iptables apply requires iptables_enabled=true and confirm_apply=APPLY_IPTABLES')
    result = RuleUpdateService(database_path).apply_enabled_rules(dry_run=dry_run)
    return jsonify(result)


@api.get('/traffic/recent')
def traffic_recent():
    """Return recent non-SSH traffic log items for monitor display."""
    return jsonify({'items': list_logs(_database_path(), limit=50, exclude_ssh=True)})
