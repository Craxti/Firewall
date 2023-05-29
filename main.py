from firewall.rule_parser import parse_rules
from firewall.firewall import Firewall
from firewall.packet import Packet, ARPPacket
from firewall.event_handler import EventHandler
from firewall.logging import setup_logging
from firewall.connection_tracker import ConnectionTracker, Connection
from firewall.network import NetworkInterface
from firewall.threat_detection import ThreatDetector, MachineLearningRule
import asyncio
import logging


async def process_packets():
    # Parsing rules from a file
    rules = parse_rules('config/rules.yaml')

    # Create a firewall instance
    firewall = Firewall(rules)

    # Create an event handler instance
    event_handler = EventHandler()

    # Firewall registration in event handler
    event_handler.register_event_handler('packet_processed', firewall.process_packet)

    # Instantiate the connection tracker
    connection_tracker = ConnectionTracker()

    # Create an instance of a network interface
    network_interface = NetworkInterface('eth0')

    # Create a Threat Detector Instance
    threat_detector = ThreatDetector(rules)

    # Create a Machine Learning Rule Instance
    machine_learning_rule = MachineLearningRule('Malware Detection', 'firewall/malware.h5')

    # Add the Machine Learning Rule to the Threat Detector
    threat_detector.add_rule(machine_learning_rule)

    while True:
        # Packet Processing Example
        arpppacket = ARPPacket('192.168.0.2', 'ARP', payload='ARP Payload')
        packet = Packet()
        packet.set_source_ip()
        packet.set_destination_ip('10.0.0.2')
        packet.set_protocol('TCP')
        packet.set_payload('Some payload')

        # Packet processing by the connection tracker
        connection_tracker.process_packet(packet)
        connection_tracker.process_packet(arpppacket)

        # Packet processing on the network interface
        network_interface.process_packet(packet)
        network_interface.process_packet(arpppacket)

        # Package Threat Detection
        threat_detector.detect_threats(packet)
        threat_detector.detect_threats(arpppacket)

        event_handler.handle_event('packet_processed', packet)
        event_handler.handle_event('packet_processed', arpppacket)

        # Add other packages to process
        interface = NetworkInterface("eth0")
        interface.determine_interface_speed()

        # Create a connection instance
        connection = Connection()
        connection.update_state("ESTABLISHED")

        # Add a delay
        await asyncio.sleep(1)


async def main():
    # Setting up logging
    log_file = 'logs/firewall.log'
    log_level = logging.INFO
    setup_logging(log_file, log_level)

    # Starting packet processing
    await process_packets()


if __name__ == '__main__':
    asyncio.run(main())
