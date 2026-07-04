import threading

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import sniff

from .repositories import insert_traffic_log, match_packet_rule


def packet_to_record(packet, direction):
    """Convert a Scapy IP packet into a traffic log record."""
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = 'OTHER'
    src_port = 'ANY'
    dst_port = 'ANY'

    if TCP in packet:
        protocol = 'TCP'
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif UDP in packet:
        protocol = 'UDP'
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)
    elif ICMP in packet:
        protocol = 'ICMP'

    return {
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'direction': direction,
        'packet_len': len(packet),
    }


class SnifferService:
    """Manage a background Scapy packet sniffer."""

    def __init__(self):
        """Initialize the service as stopped."""
        self.running = False
        self._stop_event = threading.Event()
        self._thread = None

    def start(self, database_path=None, interface='any'):
        """Start sniffing packets in a background thread."""
        if self.running:
            return {'running': True}
        self.running = True
        self._stop_event.clear()
        if database_path is None:
            return {'running': True}
        self._thread = threading.Thread(
            target=self._sniff,
            args=(database_path, interface),
            daemon=True,
        )
        self._thread.start()
        return {'running': True}

    def stop(self):
        """Signal the sniffer thread to stop."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self.running = False
        return {'running': False}

    def handle_packet(self, packet, database_path, direction='OUT'):
        """Convert one packet to a traffic log row and persist it."""
        record = packet_to_record(packet, direction)
        if record is None:
            return None
        matched_rule = match_packet_rule(database_path, record)
        if matched_rule:
            record['action'] = 'DENY'
            record['rule_id'] = matched_rule['id']
            record['reason'] = f"matched rule {matched_rule['id']}"
        else:
            record['action'] = 'ALLOW'
            record['rule_id'] = None
            record['reason'] = 'default allow'
        return insert_traffic_log(database_path, record)

    def _sniff(self, database_path, interface):
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=interface,
                    store=False,
                    timeout=1,
                    prn=lambda packet: self.handle_packet(packet, database_path),
                )
        finally:
            self.running = False
