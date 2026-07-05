import threading
import time

from .repositories import (
    add_system_log,
    get_settings,
    list_pending_rule_updates,
)
from .update_service import RuleUpdateService


class TimedUpdateService:
    """Periodically apply pending rule updates when timed mode is enabled."""

    def __init__(self, database_path):
        """Store database path and initialize worker state."""
        self.database_path = database_path
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        """Start the timed update worker once."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the timed update worker."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)

    def _run(self):
        """Loop until stopped and apply pending updates at configured intervals."""
        last_apply = 0
        while not self._stop_event.is_set():
            settings = get_settings(self.database_path)
            interval = max(int(settings.get('update_interval', '30')), 1)
            now = time.time()
            if now - last_apply >= interval:
                if apply_timed_updates_once(self.database_path):
                    last_apply = now
            self._stop_event.wait(1)


def apply_timed_updates_once(database_path):
    """Apply pending updates once when settings are in timed mode."""
    settings = get_settings(database_path)
    if settings.get('update_mode') != 'timed':
        return None
    pending = list_pending_rule_updates(database_path)
    if not pending:
        return None
    dry_run = settings.get('iptables_enabled') != 'true'
    result = RuleUpdateService(database_path).apply_enabled_rules(dry_run=dry_run)
    add_system_log(
        database_path,
        'INFO',
        '规则应用',
        f"定时{'模拟' if dry_run else '真实'}应用规则，命令数={result['applied_count']}",
    )
    return result
