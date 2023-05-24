import psutil
import socket
import logging
import subprocess
import re
import speedtest


class NetworkInterface:
    def __init__(self, interface_name):
        self.interface_name = interface_name
        self.interface_name = interface_name
        self.logger = logging.getLogger('firewall')
        self.ip_address = None
        self.subnet_mask = None
        self.interface_status = False
        self.host_reachable = False
        self.Speedtest = None

        self.interface_speed = 0

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

    def determine_interface_speed(self):
        try:
            output = subprocess.check_output(['ifconfig', self.interface_name], universal_newlines=True)
            speed_match = re.search(r"(\d+\.\d+)\s(Mb|Gb)", output)
            if speed_match:
                speed = float(speed_match.group(1))
                unit = speed_match.group(2)
                if unit == "Gb":
                    speed *= 1000
                self.interface_speed = speed
            else:
                self.interface_speed = 0
        except:
            self.interface_speed = 0

    def determine_internet_speed(self):
        try:
            st = speedtest.Speedtest()
            self.interface_speed = round(st.download() / 1000000, 2)
        except:
            self.interface_speed = 0

    def is_host_reachable(self, host):
        try:
            response = subprocess.call(["ping", "-c", "1", host], stdout=subprocess.DEVNULL)
            return response == 0
        except:
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

    def __str__(self):
        return f"Interface Name: {self.interface_name}, IP Address: {self.get_ip_address()}, " \
               f"Subnet Mask: {self.get_subnet_mask()}, Interface Status: {self.get_interface_status()}, " \
               f"Interface Speed: {self.interface_speed} Mbps"
