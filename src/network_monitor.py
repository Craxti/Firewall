import logging
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send


class NetworkMonitor:
    def __init__(self):
        self.logger = logging.getLogger("NetworkMonitor")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())

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
                    self.logger.warning("Potential SSH intrusion detected!")

            elif UDP in ip_packet:
                udp_packet = ip_packet[UDP]
                self.logger.info("UDP Source Port: %s", udp_packet.sport)
                self.logger.info("UDP Destination Port: %s", udp_packet.dport)

                # UDP
                if udp_packet.dport == 53:
                    self.logger.warning("Potential DNS intrusion detected!")

            elif ICMP in ip_packet:
                icmp_packet = ip_packet[ICMP]
                self.logger.info("ICMP Type: %s", icmp_packet.type)
                self.logger.info("ICMP Code: %s", icmp_packet.code)

                # ICMP
                if icmp_packet.type == 8:
                    self.logger.warning("Potential ICMP Echo Request (Ping) intrusion detected!")

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
                    self.logger.warning("Potential SSH intrusion detected!")

            elif UDP in ipv6_packet:
                udp_packet = ipv6_packet[UDP]
                self.logger.info("UDP Source Port: %s", udp_packet.sport)
                self.logger.info("UDP Destination Port: %s", udp_packet.dport)

                # UDP
                if udp_packet.dport == 53:
                    self.logger.warning("Potential DNS intrusion detected!")

        else:
            self.logger.warning("Unsupported packet type: %s", packet.summary())

    def block_threat(self, packet):
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet.dst, dst=packet.src) / icmp_error / packet
        send(response_packet, iface="eth0")

    def start_monitoring(self):
        self.logger.info("Starting network monitoring...")
        sniff(prn=self.process_packet)


if __name__ == "__main__":
    network_monitor = NetworkMonitor()
    network_monitor.start_monitoring()
