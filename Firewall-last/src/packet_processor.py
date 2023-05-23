from abc import ABC, abstractmethod
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import ICMPv6ND_NS
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
import asyncio
import logging

from src.action import BlockAction, AllowAction, LogAction


class PacketProcessor(ABC):
    @abstractmethod
    def process(self, packet):
        raise NotImplementedError("process() method must be implemented in subclasses.")


class CustomPacketProcessor(PacketProcessor):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def process(self, packet):
        self.logger.info("Custom packet processing:")
        self.logger.info("Source MAC: %s", packet[Ether].src)
        self.logger.info("Destination MAC: %s", packet[Ether].dst)

        if IP in packet:
            # IP Packet Handling
            self.logger.info("IP Packet:")
            self.logger.info("Source IP: %s", packet[IP].src)
            self.logger.info("Destination IP: %s", packet[IP].dst)
            self.logger.info(".")

            if Raw in packet:
                if b"malware" in packet[Raw].load:
                    self.logger.info("Detected malware traffic.")
                else:
                    self.logger.info("No malware detected.")
            else:
                self.logger.info("Packet does not contain Raw layer.")

        # Packet Processing Logic Example:
        # - If the package has a specific source and destination, send a new package
        if packet.haslayer(IP) and packet[IP].src == "192.168.1.10" and packet[IP].dst == "192.168.1.20":
            new_packet = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load="Modified payload")
            sendp(new_packet)

        # - If a packet contains a specific sequence of bytes in the payload, block it
        if packet.haslayer(Raw):
            if b"malware" in packet[Raw].load:
                self.logger.info("Detected malware.")

    @staticmethod
    def check_traffic_anomaly_condition(packet):
        payload_len = len(packet[Raw].load)
        if len(packet) > 1000 and TCP in packet and packet[TCP].flags == "S":
            print("Detected traffic anomaly.")
            return True
        return False


class MyPacketProcessor(CustomPacketProcessor):
    def process(self, packet):
        super().process(packet)

        if IP in packet:
            print("IP Packet:")
            print("Source IP:", packet[IP].src)
            print("Destination IP:", packet[IP].dst)
            # IP Packet Handling
            self.logger.info("IP Packet:")
            self.logger.info("Source IP: %s", packet[IP].src)
            self.logger.info("Destination IP: %s", packet[IP].dst)
        else:
            print("Packet does not contain IP layer.")
            self.logger.info("Packet does not contain IP layer.")

        if Raw in packet:
            if b"malware" in packet[Raw].load:
                print("Detected malware traffic.")
                self.logger.info("Detected malware traffic.")
            else:
                self.logger.info("No malware detected.")
        else:

            self.logger.info("Packet does not contain Raw layer.")

        if packet[IP].src == "192.168.1.10" and packet[IP].dst == "192.168.1.20":
            new_packet = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load="Modified payload")
            sendp(new_packet)

        if packet.haslayer(Raw):
            if b"malware" in packet[Raw].load:
                self.logger.info("Detected malware.")

    def block_malicious_packet(self, packet):
        # Implement your logic for blocking a malicious packet
        print("Blocking malicious packet:", packet.summary())
        self.logger.info("Blocking malicious packet: %s", packet.summary())

        # Drop the packet
        # Example: You can simply return here to drop the packet

        # Send a response indicating the detection of malware
        # Example: You can use scapy to send an ICMP error message to the sender
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / icmp_error / packet[IP]
        sendp(response_packet, iface="eth0")  # Replace "eth0" with the appropriate network interface


class PacketProcessorManager:
    def __init__(self):
        self.processors = []
        self.priority_processors = {}
        self.logger = logging.getLogger(__name__)

    def register_processor(self, processor, priority=0):
        self.processors.append(processor)
        self._add_to_priority_processors(processor, priority)

    def unregister_processor(self, processor):
        if processor in self.processors:
            self.processors.remove(processor)
            self._remove_from_priority_processors(processor)

    def _add_to_priority_processors(self, processor, priority):
        if priority in self.priority_processors:
            self.priority_processors[priority].append(processor)
        else:
            self.priority_processors[priority] = [processor]

    def _remove_from_priority_processors(self, processor):
        for priority, processors in self.priority_processors.items():
            if processor in processors:
                processors.remove(processor)
                if not processors:  # Remove priority if no processors left
                    del self.priority_processors[priority]

    def process_packet(self, packet_data):
        incoming_packet = Ether(packet_data)
        print("Processing packet:", incoming_packet.summary())
        self.logger.info("Processing packet: %s", incoming_packet.summary())

        # Extract the payload from the Raw layer
        raw_layer = incoming_packet.getlayer(Raw)
        if raw_layer:
            ip_payload = raw_layer.load
        else:
            ip_payload = b""

        matched_rules = self._get_matched_rules(incoming_packet, ip_payload)
        for rule in matched_rules:
            self._process_rule(rule, incoming_packet)
            if rule.action.stops_processing:
                break

        self._process_packet_processors(incoming_packet)

    def _get_matched_rules(self, packet, payload):
        matched_rules = []
        # Implement your rule matching logic here
        # Example: Iterate over a list of rules and check if the packet matches each rule's conditions
        for rule in matched_rules:
            if rule.matches(packet, payload):
                matched_rules.append(rule)
        return matched_rules

    def _process_rule(self, rule, packet):
        # Perform the specified action for the matched rule
        if isinstance(rule.action, BlockAction):
            print("Blocking packet:", packet.summary())
            self.logger.info("Blocking packet: %s", packet.summary())
            # Implement your code to block the packet
        elif isinstance(rule.action, AllowAction):
            print("Allowing packet:", packet.summary())
            self.logger.info("Allowing packet: %s", packet.summary())
            # Implement your code to allow the packet
        elif isinstance(rule.action, LogAction):
            print("Logging packet:", packet.summary())
            self.logger.info("Logging packet: %s", packet.summary())
            # Implement your code to log the packet
        else:
            print("Unsupported action for rule:", rule)
            self.logger.warning("Unsupported action for rule: %s", rule)

    def _process_packet_processors(self, packet):
        for processor in self.processors:
            processor.process(packet)


class ICMPProcessor(PacketProcessor):
    def process(self, packet):
        icmp = packet.getlayer(ICMP)
        if icmp:
            logging.info("ICMP packet: %s", packet.summary())
        else:
            super().process(packet)


class TCPProcessor(PacketProcessor):
    def process(self, packet):
        tcp = packet.getlayer(TCP)
        if tcp:
            logging.info("TCP packet: %s", packet.summary())
        else:
            super().process(packet)


class UDPProcessor(CustomPacketProcessor):
    def process(self, packet):
        udp = packet.getlayer(UDP)
        if udp:
            logging.info("UDP packet: %s", packet.summary())
        else:
            logging.info("Not a UDP packet.")


class ARPProcessor(CustomPacketProcessor):
    def process(self, packet):
        arp = packet.getlayer(ARP)
        if arp:
            logging.info("ARP packet: %s", packet.summary())
        else:
            logging.info("Not an ARP packet.")


class ICMPv6Processor(CustomPacketProcessor):
    def process(self, packet):
        icmpv6 = packet.getlayer(ICMPv6ND_NS)
        if icmpv6:
            logging.info("ICMPv6 packet: %s", packet.summary())
        else:
            logging.info("Not an ICMPv6 packet.")


class DNSProcessor(CustomPacketProcessor):
    def process(self, packet):
        dns = packet.getlayer(DNS)
        if dns:
            logging.info("DNS packet: %s", packet.summary())
        else:
            logging.info("Not a DNS packet.")


class HTTPProcessor(CustomPacketProcessor):
    def process(self, packet):
        http = packet.getlayer(HTTP)
        if http:
            logging.info("HTTP packet: %s", packet.summary())
        else:
            logging.info("Not an HTTP packet.")


class MalwareDetectionProcessor(CustomPacketProcessor):
    def __init__(self, malware_signatures=None):
        super().__init__()
        self.malware_signatures = malware_signatures or []

    def add_malware_signature(self, signature):
        self.malware_signatures.append(signature)

    def remove_malware_signature(self, signature):
        if signature in self.malware_signatures:
            self.malware_signatures.remove(signature)

    def process(self, packet):
        if self.is_malware(packet):
            self.block_malicious_packet(packet)
        else:
            self.logger.info("No malware detected.")

    def is_malware(self, packet):
        if Raw in packet:
            payload = packet[Raw].load
            if any(signature in payload for signature in self.malware_signatures):
                return True
        return False

    def block_malicious_packet(self, packet):
        # Implement your logic for blocking a malicious packet
        # Example: Drop the packet or send a response indicating malicious activity
        self.logger.info("Blocking malicious packet: %s", packet.summary())
        # Add your code to block the packet here
        # For example, you can use scapy to send an ICMP error message to the sender
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / icmp_error / packet[IP]
        sendp(response_packet, iface="eth0")  # Replace "eth0" with the appropriate network interface


class TrafficBehaviorAnalysisProcessor(CustomPacketProcessor):
    def process(self, packet):
        if self.has_traffic_anomaly(packet):
            self.logger.info("Traffic behavior anomaly detected: %s", packet.summary())
        else:
            self.logger.info("No traffic behavior anomaly detected.")

    def has_traffic_anomaly(self, packet):
        # Implement your traffic behavior analysis logic here
        # Example: Analyze traffic patterns or detect anomalies in the packet
        return self.check_traffic_anomaly(packet)

    def check_traffic_anomaly(self, packet):
        # Replace this with your actual implementation
        # Example: Perform statistical analysis or rule-based checks on the packet
        return self.check_traffic_anomaly_condition(packet)

    @staticmethod
    def check_traffic_anomaly_condition(packet):
        try:
            return packet.size > 1000 and packet.haslayer(TCP) and packet[TCP].flags == "S"
        except (AttributeError, IndexError):
            return False


class PacketProcessorObserver:
    def update(self, packet):
        raise NotImplementedError("update() method must be implemented in subclasses.")


class DynamicPacketProcessor(CustomPacketProcessor):
    def __init__(self):
        super().__init__()
        self.processors = []
        self.observers = []
        self.logger = logging.getLogger(__name__)

    def register_processor(self, processor):
        self.processors.append(processor)

    def unregister_processor(self, processor):
        if processor in self.processors:
            self.processors.remove(processor)

    def register_observer(self, observer):
        self.observers.append(observer)

    def unregister_observer(self, observer):
        if observer in self.observers:
            self.observers.remove(observer)

    async def process(self, packet):
        tasks = []
        for processor in self.processors:
            tasks.append(processor.process(packet))
        await asyncio.gather(*tasks)

        for observer in self.observers:
            observer.update(packet)

    def set_processor_order(self, processor_order):
        """
        Set the order of processor execution.

        :param processor_order: List of processor instances in the desired execution order.
        """
        self.processors = processor_order

    def prioritize_processor(self, processor, priority):
        """
        Set the priority of a processor.

        :param processor: The processor instance.
        :param priority: The priority value. Processors with lower values will be executed first.
        """
        for idx, proc in enumerate(self.processors):
            if proc == processor:
                self.processors.pop(idx)
                self.processors.insert(priority, processor)
                break

    async def process_packet(self, packet_data):
        incoming_packet = Ether(packet_data)
        self.logger.info("Processing packet: %s", incoming_packet.summary())

        # Extract the payload from the Raw layer
        raw_layer = incoming_packet.getlayer(Raw)
        if raw_layer:
            ip_payload = raw_layer.load
        else:
            ip_payload = b""

        matched_rules = self._get_matched_rules(incoming_packet, ip_payload)
        for rule in matched_rules:
            await self._process_rule(rule, incoming_packet)
            if rule.action.stops_processing:
                break

        await self.process(incoming_packet)

    async def _process_rule(self, rule, packet):
        # Perform the specified action for the matched rule
        if isinstance(rule.action, BlockAction):
            self.logger.info("Blocking packet: %s", packet.summary())
            # Implement your code to block the packet
        elif isinstance(rule.action, AllowAction):
            self.logger.info("Allowing packet: %s", packet.summary())
            # Implement your code to allow the packet
        elif isinstance(rule.action, LogAction):
            self.logger.info("Logging packet: %s", packet.summary())
            # Implement your code to log the packet
        else:
            self.logger.info("Unsupported action for rule: %s", rule)

    def _get_matched_rules(self, packet, payload):
        matched_rules = []
        # Implement your rule matching logic here
        # Example: Iterate over a list of rules and check if the packet matches each rule's conditions
        for rule in matched_rules:
            if rule.matches(packet, payload):
                matched_rules.append(rule)
        return matched_rules
