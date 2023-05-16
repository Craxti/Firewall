from abc import ABC, abstractmethod
import smtplib

from scapy.all import *
from scapy.layers.inet import IP, TCP
from cryptography.fernet import Fernet


class Action(ABC):
    @abstractmethod
    def process(self, incoming_packet):
        raise NotImplementedError("process() method must be implemented in subclasses.")


class BlockAction(Action):

    logger = logging.getLogger("BlockAction")

    def __init__(self):
        self.stops_processing = False

    def process(self, incoming_packet):
        self.logger.info("Block packet: %s", incoming_packet.summary())
#        incoming_packet.drop()


class AllowAction(Action):

    logger = logging.getLogger("AllowAction")

    def process(self, incoming_packet):
        self.logger.info("Allow packet: %s", incoming_packet.summary())
        incoming_packet.accept()


class LogAction(Action):

    logger = logging.getLogger("LogAction")

    def __init__(self, log_file):
        self.log_file = log_file

    def process(self, incoming_packet):
        self.logger.info("Logged packet: %s", incoming_packet.summary())
        with open(self.log_file, "a") as f:
            f.write(f"Logged packet: {incoming_packet.summary()}\n")
        incoming_packet.accept()


class InterfaceBlockAction(Action):

    logger = logging.getLogger("InterfaceBlockAction")

    def __init__(self, interface):
        self.interface = interface

    def process(self, incoming_packet):
        self.logger.info("Block packet on interface %s: %s", self.interface, incoming_packet.summary())
        sendp(incoming_packet, iface=self.interface, verbose=False)


class RedirectAction(Action):
    def __init__(self, dst_host, dst_port):
        self.dst_host = dst_host
        self.dst_port = dst_port

    def process(self, incoming_packet):
        incoming_packet[IP].dst = self.dst_host
        incoming_packet[TCP].dport = self.dst_port
        send(incoming_packet, verbose=False)


class EmailNotificationAction(Action):
    def __init__(self, smtp_server, sender_email, receiver_email, subject):
        self.smtp_server = smtp_server
        self.sender_email = sender_email
        self.receiver_email = receiver_email
        self.subject = subject

    def process(self, incoming_packet):
        message = f"Blocked packet: {incoming_packet.summary()}"
        msg = f"Subject: {self.subject}\n\n{message}"

        with smtplib.SMTP(self.smtp_server) as server:
            server.sendmail(self.sender_email, self.receiver_email, msg)



class EncryptionAction(Action):
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key

    def process(self, incoming_packet):
        # Encrypt the packet payload or specific fields using the encryption key
        # Example using Fernet symmetric encryption
        cipher = Fernet(self.encryption_key)
        encrypted_payload = cipher.encrypt(incoming_packet.payload)
        incoming_packet.payload = encrypted_payload

class DecryptionAction(Action):
    def __init__(self, decryption_key):
        self.decryption_key = decryption_key

    def process(self, incoming_packet):
        # Decrypt the packet payload or specific fields using the decryption key
        # Example using Fernet symmetric decryption
        cipher = Fernet(self.decryption_key)
        decrypted_payload = cipher.decrypt(incoming_packet.payload)
        incoming_packet.payload = decrypted_payload


class ModifyHeadersAction(Action):
    def __init__(self, headers):
        self.headers = headers

    def process(self, incoming_packet):
        # Modify specific header fields of the packet
        # Example: Modifying the source IP and destination port of an IP/TCP packet
        if IP in incoming_packet and TCP in incoming_packet:
            incoming_packet[IP].src = self.headers.get('source_ip', incoming_packet[IP].src)
            incoming_packet[TCP].dport = self.headers.get('destination_port', incoming_packet[TCP].dport)


class CombinedAction(Action):
    def __init__(self, actions):
        self.actions = actions

    def process(self, incoming_packet):
        for action in self.actions:
            action.process(incoming_packet)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
