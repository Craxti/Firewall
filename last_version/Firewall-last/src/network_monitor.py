import logging
from scapy.all import sniff
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send


class NetworkMonitor:
    def __init__(self):
        self.logger = logging.getLogger("NetworkMonitor")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())
        self.statistics = {
            "total_packets": 0,
            "threat_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "dns_intrusions": 0,
            "ssh_intrusions": 0,
        }

        self.anomaly_threshold = 1000

    def process_packet(self, packet):
        self.logger.info("Analyzing packet: %s", packet.summary())

        if IP in packet:
            ip_packet = packet[IP]
            self.logger.info("Source IP: %s", ip_packet.src)
            self.logger.info("Destination IP: %s", ip_packet.dst)

            # IPv4
            if TCP in ip_packet:
                tcp_packet = ip_packet[TCP]
                self.logger.info("TCP Source Port: %s", tcp_packet.sport)
                self.logger.info("TCP Destination Port: %s", tcp_packet.dport)

                # TCP
                if tcp_packet.dport == 22:
                    self.logger.info("Potential SSH intrusion detected!")

                    self.notify_anomaly(ip_packet.src)

            elif UDP in ip_packet:
                udp_packet = ip_packet[UDP]
                self.logger.info("UDP Source Port: %s", udp_packet.sport)
                self.logger.info("UDP Destination Port: %s", udp_packet.dport)

                # UDP
                if udp_packet.dport == 53:
                    self.logger.info("Potential DNS intrusion detected!")

                    self.notify_anomaly(ip_packet.src)

        elif IPv6 in packet:
            ipv6_packet = packet[IPv6]
            self.logger.info("Source IPv6: %s", ipv6_packet.src)
            self.logger.info("Destination IPv6: %s", ipv6_packet.dst)

            # IPv6
            if TCP in ipv6_packet:
                tcp_packet = ipv6_packet[TCP]
                self.logger.info("TCP Source Port: %s", tcp_packet.sport)
                self.logger.info("TCP Destination Port: %s", tcp_packet.dport)

                # TCP
                if tcp_packet.dport == 22:
                    self.logger.info("Potential SSH intrusion detected!")

                    self.notify_anomaly(ipv6_packet.src)

            elif UDP in ipv6_packet:
                udp_packet = ipv6_packet[UDP]
                self.logger.info("UDP Source Port: %s", udp_packet.sport)
                self.logger.info("UDP Destination Port: %s", udp_packet.dport)

                # UDP
                if udp_packet.dport == 53:
                    self.logger.info("Potential DNS intrusion detected!")

                    self.notify_anomaly(ipv6_packet.src)

        else:
            self.logger.info("Unsupported packet type: %s", packet.summary())

        self.statistics["total_packets"] += 1

    def start_monitoring(self):
        self.logger.info("Starting network monitoring...")
        sniff(prn=self.process_packet)

    def block_threat(self, packet):
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet.dst, dst=packet.src) / icmp_error / packet
        send(response_packet, iface="eth0")

    def notify_anomaly(self, source_ip):
        # Реализовать механизм отправки уведомления об аномалии
        self.logger.info("Anomaly detected from IP: %s", source_ip)

    def detect_anomalous_activity(self):
        self.logger.info("Detecting anomalous activity...")

    def print_statistics(self):
        self.logger.info("Network Monitoring Statistics:")
        self.logger.info("Total packets analyzed: %d", self.statistics["total_packets"])
        self.logger.info("Threat packets detected: %d", self.statistics["threat_packets"])
        self.logger.info("TCP packets: %d", self.statistics["tcp_packets"])
        self.logger.info("UDP packets: %d", self.statistics["udp_packets"])
        self.logger.info("DNS intrusions detected: %d", self.statistics["dns_intrusions"])
        self.logger.info("SSH intrusions detected: %d", self.statistics["ssh_intrusions"])

    def multi_interface_support(self, interfaces):
        self.logger.info("Monitoring multiple interfaces...")
        for interface in interfaces:
            self.logger.info("Monitoring interface: %s", interface)
            sniff(prn=self.process_packet, iface=interface)

    def packet_content_analysis(self):
        self.logger.info("Analyzing packet content...")


if __name__ == "__main__":
    network_monitor = NetworkMonitor()
    network_monitor.start_monitoring()
