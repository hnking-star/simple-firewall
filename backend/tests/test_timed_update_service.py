from app.db import init_db
from app.repositories import create_rule, get_settings, list_pending_rule_updates, update_settings, add_rule_update
from app.rule_parser import RuleParser
from app.timed_update_service import apply_timed_updates_once


def test_apply_timed_updates_once_applies_pending_rules(db_path):
    init_db(str(db_path))
    update_settings(str(db_path), {
        'update_mode': 'timed',
        'iptables_enabled': False,
    })
    rule = RuleParser.parse('DENY IN ICMP FROM ANY TO ANY SPORT ANY DPORT ANY')
    created = create_rule(str(db_path), rule, 'block icmp')
    add_rule_update(str(db_path), created['id'], 'CREATE')

    result = apply_timed_updates_once(str(db_path))

    assert result['status'] == 'APPLIED'
    assert result['pending_update_count'] == 1
    assert list_pending_rule_updates(str(db_path)) == []
    assert get_settings(str(db_path))['update_mode'] == 'timed'


def test_apply_timed_updates_once_ignores_non_timed_mode(db_path):
    init_db(str(db_path))

    assert apply_timed_updates_once(str(db_path)) is None
