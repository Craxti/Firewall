import asyncio
import logging
from src.firewall import Firewall
from src.rule import FirewallRule, Rule, IPCondition, PortCondition, AndCondition, OrCondition, NotCondition
from src.condition import IPCondition, PortCondition
from src.action import BlockAction, AllowAction, LogAction, InterfaceBlockAction, RedirectAction
from src.packet_processor import DynamicPacketProcessor, CustomPacketProcessor, MalwareDetectionProcessor, TrafficBehaviorAnalysisProcessor

if __name__ == "__main__":
    firewall = Firewall()

    # Adding rule to allow specific IP addresses
    allow_ip_condition = IPCondition("192.168.1.1")
    allow_ip_action = AllowAction()
    allow_ip_rule = FirewallRule(allow_ip_condition, allow_ip_action)
    firewall.add_rule(allow_ip_rule)

    # Adding rule to block port 80
    block_port_condition = PortCondition(80)
    block_port_action = BlockAction()
    block_port_rule = FirewallRule(block_port_condition, block_port_action)
    firewall.add_rule(block_port_rule)

    # Adding rule to log packets
    log_condition = IPCondition("192.168.1.2")
    log_action = LogAction("firewall.log")
    log_rule = FirewallRule(log_condition, log_action)
    firewall.add_rule(log_rule)

    # Adding rule to block packets on a specific interface
    interface_block_condition = IPCondition("192.168.1.3")
    interface_block_action = InterfaceBlockAction("eth0")
    interface_block_rule = FirewallRule(interface_block_condition, interface_block_action)
    firewall.add_rule(interface_block_rule)

    # Adding rule to redirect packets to another host and port
    redirect_condition = IPCondition("192.168.1.4")
    redirect_action = RedirectAction("192.168.1.10", 8080)
    redirect_rule = FirewallRule(redirect_condition, redirect_action)
    firewall.add_rule(redirect_rule)

    # Create IP conditions
    ip_condition_1 = IPCondition("192.168.1.1")
    ip_condition_2 = IPCondition("192.168.1.2")
    # Create port conditions
    port_condition_1 = PortCondition(80)
    port_condition_2 = PortCondition(443)
    # Combine conditions using logical operators
    combined_condition = AndCondition(ip_condition_1, port_condition_1)  # Match packets with IP 192.168.1.1 and port 80
    or_condition = OrCondition(ip_condition_2, port_condition_2)  # Match packets with IP 192.168.1.2 or port 443
    not_condition = NotCondition(ip_condition_1)  # Match packets that do not have IP 192.168.1.1
    # Create actions
    block_action = BlockAction()
    allow_action = AllowAction()
    log_action = LogAction("firewall.log")
    # Create rules with the new composite conditions and actions
    rule_1 = Rule(combined_condition, block_action)
    rule_2 = Rule(or_condition, allow_action)
    rule_3 = Rule(not_condition, log_action)

    # Create custom packet processors
    custom_packet_processor = CustomPacketProcessor()
    malware_processor = MalwareDetectionProcessor()
    traffic_processor = TrafficBehaviorAnalysisProcessor()

    # Create dynamic packet processor and register the custom packet processors
    dynamic_packet_processor = DynamicPacketProcessor()
    dynamic_packet_processor.register_processor(custom_packet_processor)
    dynamic_packet_processor.register_processor(malware_processor)
    dynamic_packet_processor.register_processor(traffic_processor)

    # Add the dynamic packet processor to the firewall
    firewall.add_packet_processor(dynamic_packet_processor)

    # Add the custom packet processors to the firewall
    firewall.add_packet_processor(custom_packet_processor)
    firewall.add_packet_processor(malware_processor)
    firewall.add_packet_processor(traffic_processor)

    # Set log level and log file for the firewall
    firewall.set_log_level(logging.INFO)
    firewall.set_log_file("firewall.log")

    # Start the firewall in an asynchronous event loop
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.ensure_future(firewall.start_sniffing()))

    # Close the event loop
    loop.close()
