import pytest

from app.rule_parser import RuleParser, RuleParserError


def test_parse_tcp_deny_out_rule():
    parsed = RuleParser.parse('DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53')
    assert parsed.action == 'DENY'
    assert parsed.direction == 'OUT'
    assert parsed.protocol == 'UDP'
    assert parsed.src_ip == 'ANY'
    assert parsed.dst_ip == '8.8.8.8'
    assert parsed.src_port == 'ANY'
    assert parsed.dst_port == '53'


def test_parse_icmp_rule_without_ports():
    parsed = RuleParser.parse('DENY IN ICMP FROM 10.0.0.5 TO ANY')
    assert parsed.protocol == 'ICMP'
    assert parsed.src_port == 'ANY'
    assert parsed.dst_port == 'ANY'


def test_reject_invalid_ip():
    with pytest.raises(RuleParserError, match='Invalid source IP'):
        RuleParser.parse('ALLOW IN TCP FROM 999.1.1.1 TO ANY SPORT ANY DPORT 80')


def test_reject_invalid_port():
    with pytest.raises(RuleParserError, match='Invalid destination port'):
        RuleParser.parse('ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT abc')
