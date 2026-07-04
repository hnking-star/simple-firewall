import subprocess


class IptablesAdapter:
    """Build and optionally run iptables commands for firewall rules."""

    IN_CHAIN = 'SIMPLE_FW_IN'
    OUT_CHAIN = 'SIMPLE_FW_OUT'

    @staticmethod
    def build_rule_command(rule):
        """Return the iptables argv list for a firewall rule."""
        chain = {'IN': IptablesAdapter.IN_CHAIN, 'OUT': IptablesAdapter.OUT_CHAIN}[rule.direction]
        target = {'ALLOW': 'ACCEPT', 'DENY': 'DROP'}[rule.action]
        protocol = rule.protocol.lower()

        command = ['iptables', '-A', chain]
        if rule.protocol != 'ANY':
            command.extend(['-p', protocol])
        if rule.src_ip != 'ANY':
            command.extend(['-s', rule.src_ip])
        if rule.dst_ip != 'ANY':
            command.extend(['-d', rule.dst_ip])
        if rule.protocol in {'TCP', 'UDP'}:
            if rule.src_port != 'ANY':
                command.extend(['--sport', IptablesAdapter._format_port(rule.src_port)])
            if rule.dst_port != 'ANY':
                command.extend(['--dport', IptablesAdapter._format_port(rule.dst_port)])
        command.extend(['-j', target])
        return command

    @classmethod
    def prepare_commands(cls):
        """Return commands that create and hook this system's chains."""
        return [
            ['sh', '-c', f'iptables -N {cls.IN_CHAIN} 2>/dev/null || true'],
            ['sh', '-c', f'iptables -N {cls.OUT_CHAIN} 2>/dev/null || true'],
            ['iptables', '-F', cls.IN_CHAIN],
            ['iptables', '-F', cls.OUT_CHAIN],
            ['sh', '-c', f'iptables -C INPUT -j {cls.IN_CHAIN} 2>/dev/null || iptables -I INPUT 1 -j {cls.IN_CHAIN}'],
            ['sh', '-c', f'iptables -C OUTPUT -j {cls.OUT_CHAIN} 2>/dev/null || iptables -I OUTPUT 1 -j {cls.OUT_CHAIN}'],
        ]

    @classmethod
    def clear_commands(cls):
        """Return commands that remove only this system's iptables hooks/rules."""
        return [
            ['sh', '-c', f'while iptables -D INPUT -j {cls.IN_CHAIN} 2>/dev/null; do :; done'],
            ['sh', '-c', f'while iptables -D OUTPUT -j {cls.OUT_CHAIN} 2>/dev/null; do :; done'],
            ['sh', '-c', f'iptables -F {cls.IN_CHAIN} 2>/dev/null || true'],
            ['sh', '-c', f'iptables -F {cls.OUT_CHAIN} 2>/dev/null || true'],
        ]

    @staticmethod
    def run(command, dry_run=True):
        """Run a command or return a dry-run result without executing it."""
        if dry_run:
            return {'command': command, 'returncode': 0, 'stdout': '', 'stderr': ''}

        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            'command': command,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
        }

    @classmethod
    def run_many(cls, commands, dry_run=True):
        """Run multiple iptables commands and return each command result."""
        return [cls.run(command, dry_run=dry_run) for command in commands]

    @staticmethod
    def _format_port(port):
        """Convert DSL port ranges to iptables range syntax."""
        return port.replace('-', ':')
