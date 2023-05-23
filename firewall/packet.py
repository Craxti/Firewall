import ipaddress
import socket


class Packet:
    def __init__(self):
        self._payload = None
        self.protocol = None
        self._source_ip = None
        self._destination_ip = None
        self._protocol = None
        self.source_ip = None
        self.destination_ip = None

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
        valid_protocols = ["TCP", "UDP", "ICMP"]
        if protocol not in valid_protocols:
            raise ValueError(f"Invalid protocol. Valid protocols are: {', '.join(valid_protocols)}")
        self._protocol = protocol

    def get_source_ip(self):
        return self.source_ip

    def get_destination_ip(self):
        return self.destination_ip

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
        return f"Source IP: {self._source_ip}, Destination IP: {self._destination_ip}, " \
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

    def set_hardware_type(self, hardware_type):
        self._hardware_type = hardware_type

    def set_operation(self, operation):
        self._operation = operation

    def get_hardware_type(self):
        return self._hardware_type

    def get_operation(self):
        return self._operation
