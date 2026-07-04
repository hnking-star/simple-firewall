import subprocess


class IptablesAdapter:
    """Build and optionally run iptables commands for firewall rules."""

    @staticmethod
    def build_rule_command(rule):
        """Return the iptables argv list for a firewall rule."""
        chain = {'IN': 'INPUT', 'OUT': 'OUTPUT'}[rule.direction]
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

    @staticmethod
    def _format_port(port):
        """Convert DSL port ranges to iptables range syntax."""
        return port.replace('-', ':')
