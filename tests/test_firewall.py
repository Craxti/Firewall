import unittest
from scapy.all import Raw
from scapy.layers.inet import IP, Ether, TCP
from src.firewall import Firewall


class FirewallTest(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall()

    def test_process_packet_no_malware(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.79.51.30") / \
                 TCP(sport=33387, dport=446, flags="A") / \
                 Raw(load=b"Hello, World!")

        result = self.firewall.process_packet(packet)
        self.assertEqual(result, None)

    def test_process_packet_with_malware(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.79.51.30") / \
                 TCP(sport=33387, dport=446, flags="A") / \
                 Raw(load=b"This is malware!")

        result = self.firewall.process_packet(packet)
        self.assertEqual(result, None)

    def test_process_packet_no_raw_layer(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.79.51.30") / \
                 TCP(sport=33387, dport=446, flags="A")

        result = self.firewall.process_packet(packet)
        self.assertEqual(result, None)


class PacketProcessorTest(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall()

    def test_check_traffic_anomaly_condition(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.130.13.220") / \
                 TCP(sport=1099, dport=443, flags="S")

        result = self.firewall.process_packet(packet)
        self.assertEqual(result, None)

    def test_check_traffic_anomaly_condition_no_tcp(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.130.13.220")

        result = self.firewall.process_packet(packet)
        self.assertFalse(result)

    def test_check_traffic_anomaly_condition_not_syn(self):
        packet = Ether(src="b4:2e:99:eb:ce:a5", dst="64:64:4a:d7:c4:09") / \
                 IP(src="192.168.31.148", dst="94.130.13.220") / \
                 TCP(sport=1099, dport=443, flags="A")

        result = self.firewall.process_packet(packet)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()