import logging
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP


class Action:
    def perform_action(self, packet):
        raise NotImplementedError


class DropAction(Action):
    def perform_action(self, packet):
        logging.debug(f"Dropping packet: {packet.summary()}")
        # Perform packet dropping logic
        packet.drop()


class AllowAction(Action):
    def perform_action(self, packet):
        logging.debug(f"Allowing packet: {packet.summary()}")
        # Perform packet allowing logic:
        packet.accept()


class LogAction(Action):
    def perform_action(self, packet):
        logging.debug(f"Logging packet: {packet.summary()}")
        log_file = open('firewall.log', 'a')
        log_file.write(f"Logged packet: {packet.summary()}\n")
        log_file.close()


class PacketHandler:
    def __init__(self, logger):
        self.logger = logger

    def process_packet(self, packet):
        raise NotImplementedError

    def process_icmp_packet(self, packet):
        raise NotImplementedError

    def process_udp_packet(self, packet):
        raise NotImplementedError

    def process_tcp_packet(self, packet):
        raise NotImplementedError

    def process_ip_packet(self, packet):
        raise NotImplementedError

    def process_ipv6_packet(self, packet):
        raise NotImplementedError

    def process_ipv4_packet(self, packet):
        raise NotImplementedError


class ProtocolHandler(PacketHandler):
    def __init__(self, logger, handlers, protocol_type):
        super().__init__(logger)
        self.handlers = handlers
        self.protocol_type = protocol_type

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing {self.protocol_type} packet: {packet.summary()}")
                scapy_packet = self.protocol_type(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing {self.protocol_type} packet: {str(e)}")

    def process_specific_packet(self, packet):
        self.process_packet(packet)


class ICMPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing ICMP packet: {packet.summary()}")
                scapy_packet = ICMP(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing ICMP packet: {str(e)}")

    def process_icmp_packet(self, packet):
        self.process_packet(packet)

    def process_specific_icmp_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific ICMP packet processing
            if packet.type == 8:  # ICMP echo request
                logging.debug("Received ICMP echo request packet")
                # Perform specific actions for ICMP echo request packet
            elif packet.type == 0:  # ICMP echo reply
                logging.debug("Received ICMP echo reply packet")
                # Perform specific actions for ICMP echo reply packet
            else:
                logging.debug("Received unknown ICMP packet")
                # Perform actions for unknown ICMP packet
        except Exception as e:
            self.logger.error(f"Error processing specific ICMP packet: {str(e)}")


class UDPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing UDP packet: {packet.summary()}")
                scapy_packet = UDP(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing UDP packet: {str(e)}")

    def process_udp_packet(self, packet):
        self.process_packet(packet)

    def process_specific_udp_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific UDP packet processing
            if packet.dport == 53:  # DNS
                logging.debug("Received DNS packet")
                # Perform specific actions for DNS packet
            elif packet.dport == 123:  # NTP
                logging.debug("Received NTP packet")
                # Perform specific actions for NTP packet
            else:
                logging.debug("Received unknown UDP packet")
                # Perform actions for unknown UDP packet
        except Exception as e:
            self.logger.error(f"Error processing specific UDP packet: {str(e)}")


class TCPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing TCP packet: {packet.summary()}")
                scapy_packet = TCP(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing TCP packet: {str(e)}")

    def process_tcp_packet(self, packet):
        self.process_packet(packet)

    def process_specific_tcp_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific TCP packet processing
            if packet.dport == 80:  # HTTP
                logging.debug("Received HTTP packet")
                # Perform specific actions for HTTP packet
            elif packet.dport == 443:  # HTTPS
                logging.debug("Received HTTPS packet")
                # Perform specific actions for HTTPS packet
            else:
                logging.debug("Received unknown TCP packet")
                # Perform actions for unknown TCP packet
        except Exception as e:
            self.logger.error(f"Error processing specific TCP packet: {str(e)}")


class IPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing IP packet: {packet.summary()}")
                scapy_packet = IP(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing IP packet: {str(e)}")

    def process_ip_packet(self, packet):
        self.process_packet(packet)

    def process_specific_ip_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific IP packet processing
            if packet.src == '192.168.0.1':
                logging.debug("Received packet from specific source IP")
                # Perform specific actions for packets from a specific source IP
            else:
                logging.debug("Received IP packet from other source")
                # Perform actions for IP packets from other sources
        except Exception as e:
            self.logger.error(f"Error processing specific IP packet: {str(e)}")


class IPv6Handler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing IPv6 packet: {packet.summary()}")
                scapy_packet = IPv6(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing IPv6 packet: {str(e)}")

    def process_ipv6_packet(self, packet):
        self.process_packet(packet)

    def process_specific_ipv6_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific IPv6 packet processing
            if packet.nh == 6:  # TCP
                logging.debug("Received TCPv6 packet")
                # Perform specific actions for TCPv6 packet
            elif packet.nh == 17:  # UDP
                logging.debug("Received UDPv6 packet")
                # Perform specific actions for UDPv6 packet
            else:
                logging.debug("Received unknown IPv6 packet")
                # Perform actions for unknown IPv6 packet
        except Exception as e:
            self.logger.error(f"Error processing specific IPv6 packet: {str(e)}")


class IPv4Handler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, Packet):
                self.logger.debug(f"Processing IPv4 packet: {packet.summary()}")
                scapy_packet = IP(packet)
                for handler in self.handlers:
                    handler.process_packet(scapy_packet)
        except Exception as e:
            self.logger.error(f"Error processing IPv4 packet: {str(e)}")

    def process_ipv4_packet(self, packet):
        self.process_packet(packet)

    def process_specific_ipv4_packet(self, packet):
        self.process_packet(packet)

        try:
            # Example logic for specific IPv4 packet processing
            if packet.src == '192.168.0.1':
                logging.debug("Received packet from specific source IP")
                # Perform specific actions for packets from a specific source IP
            else:
                logging.debug("Received IPv4 packet from other source")
                # Perform actions for IPv4 packets from other sources
        except Exception as e:
            self.logger.error(f"Error processing specific IPv4 packet: {str(e)}")


class ARPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, ARP):
                self.logger.debug(f"Processing ARP packet: {packet.summary()}")
                # Perform ARP packet processing logic
                self._process_arp_packet(packet)
                for handler in self.handlers:
                    handler.process_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing ARP packet: {str(e)}")

    def _process_arp_packet(self, packet):
        # Example logic for ARP packet processing
        # Print the ARP packet details
        self.logger.debug(f"ARP packet details:")
        self.logger.debug(f"  - Source IP: {packet.psrc}")
        self.logger.debug(f"  - Destination IP: {packet.pdst}")
        self.logger.debug(f"  - Source MAC: {packet.hwsrc}")
        self.logger.debug(f"  - Destination MAC: {packet.hwdst}")


class DNSHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, DNS):
                self.logger.debug(f"Processing DNS packet: {packet.summary()}")
                # Perform DNS packet processing logic
                self._process_dns_packet(packet)
                for handler in self.handlers:
                    handler.process_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing DNS packet: {str(e)}")

    def _process_dns_packet(self, packet):
        # Example logic for DNS packet processing
        # Print the DNS packet details
        self.logger.debug(f"DNS packet details:")
        self.logger.debug(f"  - Source IP: {packet[IP].src}")
        self.logger.debug(f"  - Destination IP: {packet[IP].dst}")
        self.logger.debug(f"  - Source Port: {packet[UDP].sport}")
        self.logger.debug(f"  - Destination Port: {packet[UDP].dport}")
        self.logger.debug(f"  - Query: {packet[DNS].qd.qname}")


class DHCPHandler(PacketHandler):
    def __init__(self, logger, handlers):
        super().__init__(logger)
        self.handlers = handlers

    def process_packet(self, packet):
        try:
            if isinstance(packet, DHCP):
                self.logger.debug(f"Processing DHCP packet: {packet.summary()}")
                # Perform DHCP packet processing logic
                self._process_dhcp_packet(packet)
                for handler in self.handlers:
                    handler.process_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing DHCP packet: {str(e)}")

    def _process_dhcp_packet(self, packet):
        # Example logic for DHCP packet processing
        # Print the DHCP packet details
        self.logger.debug(f"DHCP packet details:")
        self.logger.debug(f"  - Source IP: {packet[IP].src}")
        self.logger.debug(f"  - Destination IP: {packet[IP].dst}")
        self.logger.debug(f"  - Source Port: {packet[UDP].sport}")
        self.logger.debug(f"  - Destination Port: {packet[UDP].dport}")
        self.logger.debug(f"  - Transaction ID: {packet[DHCP].xid}")


class Firewall:
    def __init__(self, rules):
        self.rules = rules
        self.logger = logging.getLogger('firewall')
        self.handlers = []
        self.action_strategies = {
            'DROP': DropAction(),
            'ALLOW': AllowAction(),
            'LOG': LogAction()
        }

    def process_packet(self, packet):
        try:
            for handler in self.handlers:
                handler.process_packet(packet)

            for rule in self.rules:
                if rule.matches(packet):
                    self.logger.info(f"Packet matched rule: {rule}")
                    actions = rule.get_actions()
                    self._perform_actions(packet, actions)
                    return actions[0]

            self.logger.info(f"No matching rule found. Passing {packet}.")
            return 'pass'
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            return 'error'

    def _perform_actions(self, packet, actions):
        for action in actions:
            if action in self.action_strategies:
                try:
                    self.action_strategies[action].perform_action(packet)
                except Exception as e:
                    self.logger.error(f"Error performing action '{action}': {str(e)}")
            else:
                self.logger.warning(f"Unknown action: {action}")

    def _drop_packet(self, packet):
        # Perform packet dropping logic
        pass

    def _allow_packet(self, packet):
        # Perform packet allowing logic
        pass

    def _log_packet(self, packet):
        # Perform packet logging logic
        pass
