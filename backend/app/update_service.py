from .iptables_adapter import IptablesAdapter
from .models import FirewallRule
from .repositories import (
    list_enabled_rules,
    list_pending_rule_updates,
    mark_rule_updates,
)


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
        """Apply enabled rules into isolated SIMPLE_FW_IN/OUT chains."""
        pending = list_pending_rule_updates(self.database_path)
        commands = IptablesAdapter.prepare_commands()
        for row in list_enabled_rules(self.database_path):
            commands.append(IptablesAdapter.build_rule_command(dict_to_rule(row)))
        results = IptablesAdapter.run_many(commands, dry_run=dry_run)
        return self._finish(pending, results, 'dry-run apply' if dry_run else 'iptables apply')

    def clear_rules(self, dry_run=True):
        """Remove only rules and hooks created by this firewall system."""
        results = IptablesAdapter.run_many(IptablesAdapter.clear_commands(), dry_run=dry_run)
        return self._finish([], results, 'dry-run clear' if dry_run else 'iptables clear')

    def _finish(self, pending, results, message):
        """Mark pending updates and return a common operation result."""
        failed = any(result['returncode'] != 0 for result in results)
        status = 'FAILED' if failed else 'APPLIED'
        if failed:
            message = f'{message} failed'
        mark_rule_updates(
            self.database_path,
            [row['id'] for row in pending],
            status,
            message,
        )
        return {
            'applied_count': len(results),
            'pending_update_count': len(pending),
            'status': status,
            'message': message,
            'results': results,
        }
