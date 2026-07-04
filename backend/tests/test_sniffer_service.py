from scapy.layers.inet import IP, TCP

from app.sniffer_service import SnifferService, packet_to_record


def test_packet_to_record_extracts_ip_tcp_fields():
    packet = IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=12345, dport=443)

    record = packet_to_record(packet, 'OUT')

    assert record == {
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'src_port': '12345',
        'dst_port': '443',
        'protocol': 'TCP',
        'direction': 'OUT',
        'packet_len': len(packet),
    }


def test_sniffer_service_start_stop_updates_running():
    service = SnifferService()

    assert service.running is False
    assert service.start() == {'running': True}
    assert service.running is True
    assert service.stop() == {'running': False}
    assert service.running is False
