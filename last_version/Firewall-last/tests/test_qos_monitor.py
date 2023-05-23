import unittest
from scapy.layers.inet import IP
from src.qos_monitor import QoSMonitor


class TestQoSMonitor(unittest.TestCase):
    def setUp(self):
        self.qos_monitor = QoSMonitor()

    def test_detect_data_type_with_unknown_packet(self):
        packet = IP() / "Unknown packet payload"
        result = self.qos_monitor.detect_data_type(packet)
        self.assertEqual(result, "Unknown")


if __name__ == "__main__":
    unittest.main()
