from app.iptables_adapter import IptablesAdapter
from app.models import FirewallRule


def test_build_drop_output_udp_dns_rule():
    rule = FirewallRule('DENY', 'OUT', 'UDP', 'ANY', '8.8.8.8', 'ANY', '53')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'OUTPUT', '-p', 'udp', '-d', '8.8.8.8', '--dport', '53', '-j', 'DROP'
    ]


def test_build_allow_input_tcp_rule():
    rule = FirewallRule('ALLOW', 'IN', 'TCP', '192.168.1.10', 'ANY', 'ANY', '22')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '192.168.1.10', '--dport', '22', '-j', 'ACCEPT'
    ]


def test_build_any_protocol_rule_without_protocol_flags():
    rule = FirewallRule('DENY', 'IN', 'ANY', '10.0.0.0/24', 'ANY', 'ANY', 'ANY')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == ['iptables', '-A', 'INPUT', '-s', '10.0.0.0/24', '-j', 'DROP']
