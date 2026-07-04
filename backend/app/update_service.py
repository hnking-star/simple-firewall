from .iptables_adapter import IptablesAdapter
from .models import FirewallRule
from .repositories import list_enabled_rules


def dict_to_rule(row):
    """Convert a stored rule dictionary into a FirewallRule."""
    return FirewallRule(
        action=row['action'],
        direction=row['direction'],
        protocol=row['protocol'],
        src_ip=row['src_ip'],
        dst_ip=row['dst_ip'],
        src_port=row['src_port'],
        dst_port=row['dst_port'],
    )


class RuleUpdateService:
    """Apply enabled firewall rules through an iptables adapter."""

    def __init__(self, database_path):
        """Store the database path used to load rules."""
        self.database_path = database_path

    def apply_enabled_rules(self, dry_run=True):
        """Apply enabled rules and return adapter results."""
        results = []
        for row in list_enabled_rules(self.database_path):
            command = IptablesAdapter.build_rule_command(dict_to_rule(row))
            results.append(IptablesAdapter.run(command, dry_run=dry_run))
        return {'applied_count': len(results), 'results': results}
