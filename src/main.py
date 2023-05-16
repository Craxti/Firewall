from src.firewall import Firewall
from src.rule import FirewallRule
from src.condition import IPCondition, PortCondition
from src.action import BlockAction, AllowAction, LogAction, InterfaceBlockAction, RedirectAction
from src.packet_processor import CustomPacketProcessor, MalwareDetectionProcessor, TrafficBehaviorAnalysisProcessor


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

    # Adding custom packet processors
    custom_packet_processor = CustomPacketProcessor()
    malware_processor = MalwareDetectionProcessor()
    traffic_processor = TrafficBehaviorAnalysisProcessor()
    firewall.add_packet_processor(custom_packet_processor)
    firewall.add_packet_processor(malware_processor)
    firewall.add_packet_processor(traffic_processor)

    # Start the firewall
    firewall.add_packet_processor(CustomPacketProcessor())
    firewall.start_sniffing()
