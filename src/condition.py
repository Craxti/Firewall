from scapy.layers.inet import IP, TCP, UDP
from functools import lru_cache
import datetime
import logging
from src.rule import Condition


class IPCondition(Condition):
    def __init__(self, ip):
        self.ip = ip

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        ip_layer = packet.getlayer(IP)
        if ip_layer:
            return ip_layer.src == self.ip or ip_layer.dst == self.ip
        else:
            return False

    def __repr__(self):
        return f"IPCondition(ip={self.ip})"


class AndCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        return self.condition1.matches(packet) and self.condition2.matches(packet)

    def __repr__(self):
        return f"AndCondition(condition1={repr(self.condition1)}, condition2={repr(self.condition2)})"


class OrCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        return self.condition1.matches(packet) or self.condition2.matches(packet)

    def __repr__(self):
        return f"OrCondition(condition1={repr(self.condition1)}, condition2={repr(self.condition2)})"


class TimeRangeCondition(Condition):
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time

    def matches(self, packet):
        current_time = datetime.datetime.now().time()
        return self.start_time <= current_time <= self.end_time

    def __repr__(self):
        return f"TimeRangeCondition(start_time={self.start_time}, end_time={self.end_time})"


class IPRangeCondition(Condition):
    def __init__(self, start_ip, end_ip):
        self.start_ip = start_ip
        self.end_ip = end_ip

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        try:
            ip = IP(packet.payload)
            src_ip = IP(self.start_ip)
            dst_ip = IP(self.end_ip)
            return src_ip <= ip.src <= dst_ip or src_ip <= ip.dst <= dst_ip
        except (IndexError, ValueError):
            return False

    def __repr__(self):
        return f"IPRangeCondition(start_ip={self.start_ip}, end_ip={self.end_ip})"


class SubnetCondition(Condition):
    def __init__(self, subnet):
        self.subnet = subnet
        self.subnet_ip = IP(subnet)

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        try:
            ip = IP(packet.load)
            subnet_ip = IP(self.subnet)
            return ip.src in subnet_ip or ip.dst in subnet_ip
        except (IndexError, ValueError):
            return False

    def __repr__(self):
        return f"SubnetCondition(subnet={self.subnet})"


class PortCondition(Condition):
    def __init__(self, port):
        self.port = port

    @lru_cache(maxsize=None)  # cashed result
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

    def __repr__(self):
        return f"PortCondition(port={self.port})"


class HeaderCondition(Condition):
    def __init__(self, header_name, header_value):
        self.header_name = header_name
        self.header_value = header_value

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        # Check if the specified header is present and has the expected value
        return self.header_name in packet and packet[self.header_name] == self.header_value

    def __repr__(self):
        return f"HeaderCondition(header_name={self.header_name}, header_value={self.header_value})"


class ContentCondition(Condition):

    logger = logging.getLogger("ContentCondition")

    def __init__(self, content):
        self.content = content

    @lru_cache(maxsize=None)  # cashed result
    def matches(self, packet):
        # Check if the packet payload contains the specified content
        self.logger.info(self.content in packet.payload)
        return packet.payload.find(self.content) != -1

    def __repr__(self):
        return f"ContentCondition(content={self.content})"


class MetadataCondition(Condition):
    def __init__(self, metadata_key, metadata_value):
        self.metadata_key = metadata_key
        self.metadata_value = metadata_value

    def matches(self, packet):
        # Check if the specified metadata key is present and has the expected value
        return packet.metadata.get(self.metadata_key) == self.metadata_value

    def __repr__(self):
        return f"MetadataCondition(metadata_key={self.metadata_key}, metadata_value={self.metadata_value})"
