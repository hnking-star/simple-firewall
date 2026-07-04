from scapy.layers.inet import ICMP, IP, TCP, UDP


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
    """Track sniffer running state without capturing packets."""

    def __init__(self):
        """Initialize the service as stopped."""
        self.running = False

    def start(self):
        """Mark the sniffer as running."""
        self.running = True
        return {'running': self.running}

    def stop(self):
        """Mark the sniffer as stopped."""
        self.running = False
        return {'running': self.running}
