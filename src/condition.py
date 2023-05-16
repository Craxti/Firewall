from scapy.layers.inet import IP, TCP, UDP
from src.rule import Condition
import datetime


class IPCondition(Condition):
    def __init__(self, ip):
        self.ip = ip

    def matches(self, packet):
        ip_layer = packet.getlayer(IP)
        if ip_layer:
            return ip_layer.src == self.ip or ip_layer.dst == self.ip
        else:
            return False


class AndCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    def matches(self, packet):
        return self.condition1.matches(packet) and self.condition2.matches(packet)


class OrCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    def matches(self, packet):
        return self.condition1.matches(packet) or self.condition2.matches(packet)


class TimeRangeCondition(Condition):
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time

    def matches(self, packet):
        current_time = datetime.datetime.now().time()
        return self.start_time <= current_time <= self.end_time


class IPRangeCondition(Condition):
    def __init__(self, start_ip, end_ip):
        self.start_ip = start_ip
        self.end_ip = end_ip

    def matches(self, packet):
        ip = IP(packet.add_payload())
        return IP(self.start_ip) <= ip.src <= IP(self.end_ip) or IP(self.start_ip) <= ip.dst <= IP(self.end_ip)

    def __str__(self):
        return f"IPRangeCondition: {self.start_ip} - {self.end_ip}"


class SubnetCondition(Condition):
    def __init__(self, subnet):
        self.subnet = subnet

    def matches(self, packet):
        ip = IP(packet.load)
        return ip.src in IP(self.subnet) or ip.dst in IP(self.subnet)

    def __str__(self):
        return f"SubnetCondition: {self.subnet}"


class PortCondition(Condition):
    def __init__(self, port):
        self.port = port

    def matches(self, packet):
        tcp_layer = packet.getlayer(TCP)
        if tcp_layer:
            return tcp_layer.sport == self.port or tcp_layer.dport == self.port
        else:
            udp_layer = packet.getlayer(UDP)
            if udp_layer:
                return udp_layer.sport == self.port or udp_layer.dport == self.port
            else:
                return False

    def __str__(self):
        return f"PortCondition: {self.port}"


class HeaderCondition(Condition):
    def __init__(self, header_name, header_value):
        self.header_name = header_name
        self.header_value = header_value

    def matches(self, packet):
        # Check if the specified header is present and has the expected value
        return self.header_name in packet and packet[self.header_name] == self.header_value

    def __str__(self):
        return f"HeaderCondition: {self.header_name}={self.header_value}"


class ContentCondition(Condition):
    def __init__(self, content):
        self.content = content

    def matches(self, packet):
        # Check if the packet payload contains the specified content
        return self.content in packet.get_payload()

    def __str__(self):
        return f"ContentCondition: {self.content}"


class MetadataCondition(Condition):
    def __init__(self, metadata_key, metadata_value):
        self.metadata_key = metadata_key
        self.metadata_value = metadata_value

    def matches(self, packet):
        # Check if the specified metadata key is present and has the expected value
        return packet.metadata.get(self.metadata_key) == self.metadata_value

    def __str__(self):
        return f"MetadataCondition: {self.metadata_key}={self.metadata_value}"
