from flask import Blueprint, current_app, jsonify, request

from .repositories import create_rule, list_rules
from .rule_parser import RuleParser, RuleParserError

api = Blueprint('api', __name__, url_prefix='/api')


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
    dsl_text = data.get('dsl_text', '')
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
    try:
        rule = RuleParser.parse(data.get('dsl_text', ''))
    except RuleParserError as exc:
        return _bad_request(str(exc))
    return jsonify(_rule_to_dict(rule))
