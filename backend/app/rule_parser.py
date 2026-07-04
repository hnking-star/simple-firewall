import ipaddress

from app.models import FirewallRule


class RuleParserError(ValueError):
    """Raised when a firewall rule DSL string is invalid."""


class RuleParser:
    """Parse firewall rule DSL strings into FirewallRule objects."""

    ACTIONS = {'ALLOW', 'DENY'}
    DIRECTIONS = {'IN', 'OUT'}
    PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ANY'}

    @classmethod
    def parse(cls, text):
        """Parse and validate one firewall rule DSL string."""
        parts = text.split()
        if len(parts) not in (7, 11):
            raise RuleParserError('Invalid rule syntax')

        action, direction, protocol = (part.upper() for part in parts[:3])
        if action not in cls.ACTIONS:
            raise RuleParserError('Invalid action')
        if direction not in cls.DIRECTIONS:
            raise RuleParserError('Invalid direction')
        if protocol not in cls.PROTOCOLS:
            raise RuleParserError('Invalid protocol')
        if parts[3].upper() != 'FROM' or parts[5].upper() != 'TO':
            raise RuleParserError('Invalid rule syntax')

        src_ip = cls._validate_ip(parts[4], 'source')
        dst_ip = cls._validate_ip(parts[6], 'destination')
        src_port = 'ANY'
        dst_port = 'ANY'

        if len(parts) == 11:
            if parts[7].upper() != 'SPORT' or parts[9].upper() != 'DPORT':
                raise RuleParserError('Invalid rule syntax')
            src_port = cls._validate_port(parts[8], 'source')
            dst_port = cls._validate_port(parts[10], 'destination')

        return FirewallRule(
            action=action,
            direction=direction,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )

    @staticmethod
    def _validate_ip(value, label):
        """Validate an IPv4 address, CIDR network, or ANY."""
        if value.upper() == 'ANY':
            return 'ANY'
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleParserError(f'Invalid {label} IP') from exc
        if ipaddress.ip_network(value, strict=False).version != 4:
            raise RuleParserError(f'Invalid {label} IP')
        return value

    @classmethod
    def _validate_port(cls, value, label):
        """Validate a port number, range, or ANY."""
        if value.upper() == 'ANY':
            return 'ANY'
        if '-' in value:
            return cls._validate_port_range(value, label)
        if value.isdigit() and 1 <= int(value) <= 65535:
            return value
        raise RuleParserError(f'Invalid {label} port')

    @classmethod
    def _validate_port_range(cls, value, label):
        """Validate a start-end port range."""
        start, separator, end = value.partition('-')
        if (
            not separator
            or not start.isdigit()
            or not end.isdigit()
            or not 1 <= int(start) <= int(end) <= 65535
        ):
            raise RuleParserError(f'Invalid {label} port')
        return value
