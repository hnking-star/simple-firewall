from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallRule:
    """Parsed firewall rule fields from the rule DSL."""

    action: str
    direction: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: str = 'ANY'
    dst_port: str = 'ANY'
