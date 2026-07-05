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
from datetime import datetime, timedelta

from app.db import init_db
from app.repositories import create_rule, list_pending_rule_updates, update_settings, add_rule_update
from app.rule_parser import RuleParser
from app.timed_update_service import apply_due_timed_updates_once


def _queue_rule(db_path):
    rule = RuleParser.parse('DENY IN ICMP FROM ANY TO ANY SPORT ANY DPORT ANY')
    created = create_rule(str(db_path), rule, 'block icmp')
    return add_rule_update(str(db_path), created['id'], 'CREATE')


def test_due_timed_updates_wait_until_interval_passes(db_path):
    init_db(str(db_path))
    update_settings(str(db_path), {
        'update_mode': 'timed',
        'update_interval': '30',
        'iptables_enabled': False,
    })
    update = _queue_rule(db_path)
    created_at = datetime.strptime(update['created_at'], '%Y-%m-%d %H:%M:%S')

    result = apply_due_timed_updates_once(str(db_path), now=created_at + timedelta(seconds=29))

    assert result is None
    assert len(list_pending_rule_updates(str(db_path))) == 1


def test_due_timed_updates_apply_after_interval_passes(db_path):
    init_db(str(db_path))
    update_settings(str(db_path), {
        'update_mode': 'timed',
        'update_interval': '30',
        'iptables_enabled': False,
    })
    update = _queue_rule(db_path)
    created_at = datetime.strptime(update['created_at'], '%Y-%m-%d %H:%M:%S')

    result = apply_due_timed_updates_once(str(db_path), now=created_at + timedelta(seconds=30))

    assert result['status'] == 'APPLIED'
    assert list_pending_rule_updates(str(db_path)) == []
