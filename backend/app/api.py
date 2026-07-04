from flask import Blueprint, current_app, jsonify, request

from .repositories import (
    create_rule,
    get_settings,
    get_stats,
    list_logs,
    list_rules,
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


def _dsl_text(data):
    """Return valid DSL text or None when invalid."""
    value = data.get('dsl_text')
    if not isinstance(value, str) or not value:
        return None
    return value


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
    data = request.get_json(silent=True) or {}
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

    created = create_rule(
        _database_path(),
        rule,
        name,
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100),
        dsl_text=dsl_text,
    )
    return jsonify(created), 201


@api.post('/rules/parse')
def rules_parse():
    """Parse firewall rule DSL without storing it."""
    data = request.get_json(silent=True) or {}
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
    data = request.get_json(silent=True) or {}
    return jsonify(update_settings(_database_path(), data))


@api.post('/sniffer/start')
def sniffer_start():
    """Start the packet sniffer service."""
    return jsonify(sniffer_service.start())


@api.post('/sniffer/stop')
def sniffer_stop():
    """Stop the packet sniffer service."""
    return jsonify(sniffer_service.stop())


@api.post('/rules/apply')
def rules_apply():
    """Apply enabled rules through the update service."""
    data = request.get_json(silent=True) or {}
    dry_run = data.get('dry_run', True)
    result = RuleUpdateService(_database_path()).apply_enabled_rules(dry_run=dry_run)
    return jsonify(result)


@api.get('/traffic/recent')
def traffic_recent():
    """Return recent traffic log items."""
    return jsonify({'items': list_logs(_database_path())})
