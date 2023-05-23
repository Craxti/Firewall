import psutil
import socket
import logging


class NetworkInterface:
    def __init__(self, interface_name):
        self.interface_name = interface_name
        self.logger = logging.getLogger('firewall')

    def get_interface_addresses(self):
        addresses = psutil.net_if_addrs()
        return addresses

    def get_ip_address(self, family=socket.AF_INET):
        addresses = self.get_interface_addresses()
        ip_address_info = addresses.get(self.interface_name)
        if ip_address_info:
            for addr in ip_address_info:
                if addr.family == family:
                    return addr.address
        return None

    def get_subnet_mask(self, family=socket.AF_INET):
        addresses = self.get_interface_addresses()
        ip_address_info = addresses.get(self.interface_name)
        if ip_address_info:
            for addr in ip_address_info:
                if addr.family == family:
                    return addr.netmask
        return None

    def get_interface_status(self):
        interfaces = psutil.net_if_stats()
        interface_status = interfaces.get(self.interface_name)
        if interface_status:
            return interface_status.isup
        return False

    def process_packet(self, packet):
        self.logger.info(f"Processing packet on interface {self.interface_name}")

        source_ip = packet.get_source_ip()
        destination_ip = packet.get_destination_ip()
        protocol = packet.get_protocol()

        self.send_packet(packet)

    def send_packet(self, packet):
        self.logger.info(f"Sending packet on interface {self.interface_name}")

    def receive_packet(self):
        print(f"Receiving packet on interface {self.interface_name}")

    def get_mac_address(self):
        addresses = self.get_interface_addresses()
        mac_address_info = addresses.get(self.interface_name)
        if mac_address_info:
            for addr in mac_address_info:
                if addr.family == psutil.AF_LINK:
                    return addr.address
        return None
