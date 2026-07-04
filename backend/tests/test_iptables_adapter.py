from unittest.mock import Mock, patch

from app.iptables_adapter import IptablesAdapter
from app.models import FirewallRule


def test_build_drop_output_udp_dns_rule():
    rule = FirewallRule('DENY', 'OUT', 'UDP', 'ANY', '8.8.8.8', 'ANY', '53')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'SIMPLE_FW_OUT', '-p', 'udp', '-d', '8.8.8.8', '--dport', '53', '-j', 'DROP'
    ]


def test_build_allow_input_tcp_rule():
    rule = FirewallRule('ALLOW', 'IN', 'TCP', '192.168.1.10', 'ANY', 'ANY', '22')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'SIMPLE_FW_IN', '-p', 'tcp', '-s', '192.168.1.10', '--dport', '22', '-j', 'ACCEPT'
    ]


def test_build_any_protocol_rule_without_protocol_flags():
    rule = FirewallRule('DENY', 'IN', 'ANY', '10.0.0.0/24', 'ANY', 'ANY', 'ANY')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == ['iptables', '-A', 'SIMPLE_FW_IN', '-s', '10.0.0.0/24', '-j', 'DROP']


def test_run_defaults_to_dry_run_without_subprocess_call():
    command = ['iptables', '-A', 'INPUT', '-j', 'DROP']

    with patch('app.iptables_adapter.subprocess.run') as subprocess_run:
        result = IptablesAdapter.run(command)

    subprocess_run.assert_not_called()
    assert result == {'command': command, 'returncode': 0, 'stdout': '', 'stderr': ''}


def test_run_executes_subprocess_when_not_dry_run():
    command = ['iptables', '-A', 'INPUT', '-j', 'DROP']
    completed = Mock(returncode=2, stdout='out', stderr='err')

    with patch('app.iptables_adapter.subprocess.run', return_value=completed) as subprocess_run:
        result = IptablesAdapter.run(command, dry_run=False)

    subprocess_run.assert_called_once_with(command, capture_output=True, text=True, check=False)
    assert result == {'command': command, 'returncode': 2, 'stdout': 'out', 'stderr': 'err'}


def test_prepare_commands_create_and_hook_system_chains():
    commands = IptablesAdapter.prepare_commands()

    assert ['iptables', '-F', 'SIMPLE_FW_IN'] in commands
    assert ['iptables', '-F', 'SIMPLE_FW_OUT'] in commands
    assert any('iptables -I INPUT 1 -j SIMPLE_FW_IN' in command[-1] for command in commands)
    assert any('iptables -I OUTPUT 1 -j SIMPLE_FW_OUT' in command[-1] for command in commands)


def test_clear_commands_remove_only_system_chains():
    commands = IptablesAdapter.clear_commands()

    assert any('iptables -D INPUT -j SIMPLE_FW_IN' in command[-1] for command in commands)
    assert any('iptables -D OUTPUT -j SIMPLE_FW_OUT' in command[-1] for command in commands)
    assert any('iptables -F SIMPLE_FW_IN' in command[-1] for command in commands)
    assert any('iptables -F SIMPLE_FW_OUT' in command[-1] for command in commands)
