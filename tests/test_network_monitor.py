import unittest
from scapy.layers.inet import IP, TCP, UDP
from src.network_monitor import NetworkMonitor


class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        self.network_monitor = NetworkMonitor()

    def test_process_packet_with_tcp_packet(self):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80)
        result = self.network_monitor.process_packet(packet)
        self.assertIsNone(result)

    def test_process_packet_with_udp_packet(self):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=4321, dport=53)
        result = self.network_monitor.process_packet(packet)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
