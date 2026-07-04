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


def test_sniffer_handle_packet_inserts_traffic_log(db_path, db_connection):
    from app.db import init_db
    from app.repositories import create_rule, list_logs
    from app.rule_parser import RuleParser

    init_db(str(db_path))
    rule = RuleParser.parse('DENY OUT TCP FROM ANY TO 10.0.0.2 SPORT ANY DPORT 443')
    created = create_rule(str(db_path), rule, 'deny https', dsl_text='DENY OUT TCP FROM ANY TO 10.0.0.2 SPORT ANY DPORT 443')
    service = SnifferService()
    packet = IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=12345, dport=443)

    service.handle_packet(packet, str(db_path))

    logs = list_logs(str(db_path))
    assert len(logs) == 1
    assert logs[0]['action'] == 'DENY'
    assert logs[0]['rule_id'] == created['id']
    assert logs[0]['reason'] == f"matched rule {created['id']}"
