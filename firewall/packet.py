import ipaddress
import socket
import re
import time


class Packet:
    def __init__(self):
        self.payload = None
        self._payload = None
        self.protocol = None
        self._source_ip = None
        self._destination_ip = None
        self._protocol = None
        self.source_ip = None
        self.destination_ip = None
        self.packet_id = None
        self.timestamp = None

    def set_payload(self, payload):
        if payload is not None and not isinstance(payload, str):
            raise ValueError("Payload must be a string or None.")
        self._payload = payload

    def set_source_ip(self):
        self._source_ip = self._get_local_ip()

    def get_protocol(self):
        return self.protocol

    def set_destination_ip(self, destination_ip):
        if not self._is_valid_ip(destination_ip):
            raise ValueError("Invalid destination IP address.")
        self._destination_ip = destination_ip

    def set_protocol(self, protocol):
        valid_protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'ICMPv6', 'ICMPv4']
        if protocol not in valid_protocols:
            raise ValueError(f"Invalid protocol. Valid protocols are: {', '.join(valid_protocols)}")
        self._protocol = protocol

    def get_source_ip(self):
        return self.source_ip

    def get_destination_ip(self):
        return self.destination_ip

    def set_packet_id(self, packet_id):
        self.packet_id = packet_id

    def set_timestamp(self):
        self.timestamp = time.time()

    @staticmethod
    def _get_local_ip():
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address

    @staticmethod
    def _is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def __str__(self):
        return f"Packet ID: {self.packet_id}, Timestamp: {self.timestamp}, " \
               f"Source IP: {self._source_ip}, Destination IP: {self._destination_ip}, " \
               f"Protocol: {self._protocol}, Payload: {self._payload}"

    def get_source_port(self):
        if self._protocol == "TCP":
            return self._get_tcp_source_port()
        elif self._protocol == "UDP":
            return self._get_udp_source_port()
        else:
            return None

    def get_destination_port(self):
        if self._protocol == "TCP":
            return self._get_tcp_destination_port()
        elif self._protocol == "UDP":
            return self._get_udp_destination_port()
        else:
            return None

    def get_packet_length(self):
        if self._payload is not None:
            return len(self._payload)
        else:
            return 0

    def _get_tcp_source_port(self):
        if self._payload is not None:
            tcp_header = self._payload[:20]
            source_port = int.from_bytes(tcp_header[:2], byteorder='big')
            return source_port
        else:
            return None

    def _get_tcp_destination_port(self):
        if self._payload is not None:
            tcp_header = self._payload[:20]
            destination_port = int.from_bytes(tcp_header[2:4], byteorder='big')
            return destination_port
        else:
            return None

    def _get_udp_source_port(self):
        if self._payload is not None:
            udp_header = self._payload[:8]
            source_port = int.from_bytes(udp_header[:2], byteorder='big')
            return source_port
        else:
            return None

    def _get_udp_destination_port(self):
        if self._payload is not None:
            udp_header = self._payload[:8]
            destination_port = int.from_bytes(udp_header[2:4], byteorder='big')
            return destination_port
        else:
            return None


class IPv4Packet(Packet):
    def __init__(self, destination_ip, protocol, payload=None):
        super().__init__()
        self._version = 4
        self.set_destination_ip(destination_ip)
        self.set_protocol(protocol)
        self.set_payload(payload)

    def get_version(self):
        return self._version


class IPv6Packet(Packet):
    def __init__(self, destination_ip, protocol, payload=None):
        super().__init__()
        self._version = 6
        self.set_destination_ip(destination_ip)
        self.set_protocol(protocol)
        self.set_payload(payload)

    def get_version(self):
        return self._version


class ARPPacket(Packet):
    def __init__(self, destination_ip, protocol, payload=None):
        super().__init__()
        self._hardware_type = None
        self._operation = None
        self.set_destination_ip(destination_ip)
        self.set_protocol(protocol)
        self.set_payload(payload)

    def set_protocol(self, protocol):
        super().set_protocol(protocol)
        if protocol == "ARP":
            self._hardware_type = "Ethernet"
            self._operation = "Request"

    def get_hardware_type(self):
        return self._hardware_type

    def get_operation(self):
        return self._operation

    def __str__(self):
        return f"Packet ID: {self.packet_id}, Timestamp: {self.timestamp}, " \
               f"Source IP: {self._source_ip}, Destination IP: {self._destination_ip}, " \
               f"Protocol: {self._protocol}, Hardware Type: {self._hardware_type}, Operation: {self._operation}, " \
               f"Payload: {self._payload}"

    def get_payload_length(self):
        if self._payload is not None:
            return len(self._payload)
        else:
            return 0

    def get_source_mac_address(self):
        if self._payload is not None and len(self._payload) >= 14:
            source_mac_address = self._payload[6:12]
            mac_address_str = ":".join("{:02x}".format(byte) for byte in source_mac_address)
            return mac_address_str
        else:
            return None

    def get_destination_mac_address(self):
        if self._payload is not None and len(self._payload) >= 14:
            destination_mac_address = self._payload[0:6]
            mac_address_str = ":".join("{:02x}".format(byte) for byte in destination_mac_address)
            return mac_address_str
        else:
            return None

    def get_payload(self):
        return self._payload

    def set_payload(self, payload):
        super().set_payload(payload)
        if payload is not None and len(payload) >= 14:
            self._extract_arp_fields()

    def _extract_arp_fields(self):
        hardware_type_bytes = self._payload[14:16]
        operation_bytes = self._payload[20:22]
        hardware_type = int.from_bytes(hardware_type_bytes, byteorder='big')
        operation = int.from_bytes(operation_bytes, byteorder='big')

        if hardware_type == 1:
            self._hardware_type = "Ethernet"
        else:
            self._hardware_type = "Unknown"

        if operation == 1:
            self._operation = "Request"
        elif operation == 2:
            self._operation = "Reply"
        else:
            self._operation = "Unknown"

    @staticmethod
    def is_valid_mac_address(mac_address):
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(pattern, mac_address) is not None


class ICMPv6Packet(Packet):
    def __init__(self, destination_ip, protocol, payload=None):
        super().__init__()
        self._icmp_type = None
        self._icmp_code = None
        self.set_destination_ip(destination_ip)
        self.set_protocol(protocol)
        self.set_payload(payload)

    def set_protocol(self, protocol):
        super().set_protocol(protocol)
        if protocol == "ICMPv6":
            self._icmp_type = "Echo Request"
            self._icmp_code = 0

    def get_icmp_type(self):
        return self._icmp_type

    def get_icmp_code(self):
        return self._icmp_code

    def __str__(self):
        return f"Packet ID: {self.packet_id}, Timestamp: {self.timestamp}, " \
               f"Source IP: {self._source_ip}, Destination IP: {self._destination_ip}, " \
               f"Protocol: {self._protocol}, ICMP Type: {self._icmp_type}, ICMP Code: {self._icmp_code}, " \
               f"Payload: {self._payload}"

    def get_payload_length(self):
        if self._payload is not None:
            return len(self._payload)
        else:
            return 0

    def get_payload(self):
        return self._payload

    def set_payload(self, payload):
        super().set_payload(payload)
        if payload is not None and len(payload) >= 8:
            self._extract_icmp_fields()

    def _extract_icmp_fields(self):
        icmp_type_bytes = self._payload[0:1]
        icmp_code_bytes = self._payload[1:2]
        icmp_type = int.from_bytes(icmp_type_bytes, byteorder='big')
        icmp_code = int.from_bytes(icmp_code_bytes, byteorder='big')

        self._icmp_type = self._get_icmp_type_name(icmp_type)
        self._icmp_code = icmp_code

    @staticmethod
    def _get_icmp_type_name(icmp_type):
        # Define a mapping of ICMPv6 type codes to their names
        icmp_type_mapping = {
            128: "Echo Request",
            129: "Echo Reply",
            130: "Group Membership Query",
            131: "Group Membership Report",
            132: "Group Membership Reduction",
            # Add more type codes as needed
        }
        return icmp_type_mapping.get(icmp_type, "Unknown")
