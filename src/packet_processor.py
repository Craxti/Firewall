from abc import ABC, abstractmethod
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import ICMPv6ND_NS
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp

from src.action import BlockAction, AllowAction, LogAction


class PacketProcessor(ABC):
    @abstractmethod
    def process(self, packet):
        raise NotImplementedError("process() method must be implemented in subclasses.")


class CustomPacketProcessor(PacketProcessor):
    def process(self, packet):
        print("Custom packet processing:")
        print("Source MAC:", packet[Ether].src)
        print("Destination MAC:", packet[Ether].dst)

        if IP in packet:
            # IP Packet Handling
            print("IP Packet:")
            print("Source IP:", packet[IP].src)
            print("Destination IP:", packet[IP].dst)
            print(".")

            if Raw in packet:
                if b"malware" in packet[Raw].load:
                    print("Detected malware traffic.")
                else:
                    print("No malware detected.")
            else:
                print("Packet does not contain Raw layer.")

        # Packet Processing Logic Example:
        # - If the package has a specific source and destination, send a new package
        if packet.haslayer(IP) and packet[IP].src == "192.168.1.10" and packet[IP].dst == "192.168.1.20":
            new_packet = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load="Modified payload")
            sendp(new_packet)

        # - If a packet contains a specific sequence of bytes in the payload, block it
        if packet.haslayer(Raw):
            if b"malware" in packet[Raw].load:
                print("Detected malware.")

    @staticmethod
    def check_traffic_anomaly_condition(packet):
        payload_len = len(packet[Raw].load)
        if len(packet) > 1000 and TCP in packet and packet[TCP].flags == "S":
            print("Detected traffic anomaly.")


class MyPacketProcessor(CustomPacketProcessor):
    def process(self, packet):
        super().process(packet)

        if IP in packet:
            # IP Packet Handling
            print("IP Packet:")
            print("Source IP:", packet[IP].src)
            print("Destination IP:", packet[IP].dst)
        else:
            print("Packet does not contain IP layer.")

        if Raw in packet:
            if b"malware" in packet[Raw].load:
                print("Detected malware traffic.")
            else:
                print("No malware detected.")
        else:
            print("Packet does not contain Raw layer.")

        if packet[IP].src == "192.168.1.10" and packet[IP].dst == "192.168.1.20":
            new_packet = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load="Modified payload")
            sendp(new_packet)

        if packet.haslayer(Raw):
            if b"malware" in packet[Raw].load:
                print("Detected malware.")

    def block_malicious_packet(self, packet):
        # Implement your logic for blocking a malicious packet
        print("Blocking malicious packet:", packet.summary())

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
            # Implement your code to block the packet
        elif isinstance(rule.action, AllowAction):
            print("Allowing packet:", packet.summary())
            # Implement your code to allow the packet
        elif isinstance(rule.action, LogAction):
            print("Logging packet:", packet.summary())
            # Implement your code to log the packet
        else:
            print("Unsupported action for rule:", rule)

    def _process_packet_processors(self, packet):
        for processor in self.processors:
            processor.process(packet)


class ICMPProcessor(PacketProcessor):
    def process(self, packet):
        icmp = packet.getlayer(ICMP)
        if icmp:
            print("ICMP packet:", packet.summary())
        else:
            super().process(packet)


class TCPProcessor(PacketProcessor):
    def process(self, packet):
        tcp = packet.getlayer(TCP)
        if tcp:
            print("TCP packet:", packet.summary())
        else:
            super().process(packet)


class UDPProcessor(CustomPacketProcessor):
    def process(self, packet):
        udp = packet.getlayer(UDP)
        if udp:
            print("UDP packet:", packet.summary())
        else:
            print("Not a UDP packet.")


class ARPProcessor(CustomPacketProcessor):
    def process(self, packet):
        arp = packet.getlayer(ARP)
        if arp:
            print("ARP packet:", packet.summary())
        else:
            print("Not an ARP packet.")


class ICMPv6Processor(CustomPacketProcessor):
    def process(self, packet):
        icmpv6 = packet.getlayer(ICMPv6ND_NS)
        if icmpv6:
            print("ICMPv6 packet:", packet.summary())
        else:
            print("Not an ICMPv6 packet.")


class DNSProcessor(CustomPacketProcessor):
    def process(self, packet):
        dns = packet.getlayer(DNS)
        if dns:
            print("DNS packet:", packet.summary())
        else:
            print("Not a DNS packet.")


class HTTPProcessor(CustomPacketProcessor):
    def process(self, packet):
        http = packet.getlayer(HTTP)
        if http:
            print("HTTP packet:", packet.summary())
        else:
            print("Not an HTTP packet.")


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
            print("No malware detected.")

    def is_malware(self, packet):
        if Raw in packet:
            payload = packet[Raw].load
            if any(signature in payload for signature in self.malware_signatures):
                return True
        return False

    def block_malicious_packet(self, packet):
        # Implement your logic for blocking a malicious packet
        # Example: Drop the packet or send a response indicating malicious activity
        print("Blocking malicious packet:", packet.summary())
        # Add your code to block the packet here
        # For example, you can use scapy to send an ICMP error message to the sender
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / icmp_error / packet[IP]
        sendp(response_packet, iface="eth0")  # Replace "eth0" with the appropriate network interface


class TrafficBehaviorAnalysisProcessor(CustomPacketProcessor):
    def process(self, packet):
        if self.has_traffic_anomaly(packet):
            print("Traffic behavior anomaly detected:", packet.summary())
        else:
            print("No traffic behavior anomaly detected.")

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
        self.processors = []
        self.observers = []

    def register_processor(self, processor):
        self.processors.append(processor)

    def register_observer(self, observer):
        self.observers.append(observer)

    def process(self, packet):
        for processor in self.processors:
            processor.process(packet)
            for observer in self.observers:
                observer.update(packet)
