import unittest
from scapy.layers.inet import IP, TCP
from src.intrusion_detection import IntrusionDetection


class TestIntrusionDetection(unittest.TestCase):
    def setUp(self):
        self.intrusion_detection = IntrusionDetection()


    def test_process_packet_with_known_threat(self):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=22) / "Malicious payload"
        result = self.intrusion_detection.process_packet(packet)
        self.assertTrue(result)

    def test_process_packet_with_unknown_threat(self):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=80) / "Suspicious payload"
        result = self.intrusion_detection.process_packet(packet)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()