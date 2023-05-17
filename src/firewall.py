from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import heapq
import pickle
import logging
from src.condition import IPCondition
from src.action import AllowAction, BlockAction
from src.rule import FirewallRule


class Firewall:
    def __init__(self):
        self.rules = []
        self.allowlist = []
        self.blocklist = []
        self.packet_processors = []
        self.logger = logging.getLogger("Firewall")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())

        self.packet_count = 0
        self.packet_types = defaultdict(int)
        self.start_time = time.time()

    def serialize(self, file_path):
        with open(file_path, 'wb') as f:
            pickle.dump(self, f)

    @staticmethod
    def deserialize(file_path):
        with open(file_path, 'rb') as f:
            return pickle.load(f)

    def set_log_level(self, log_level):
        self.logger.setLevel(log_level)

    def set_log_file(self, log_file):
        file_handler = logging.FileHandler(log_file)
        self.logger.addHandler(file_handler)

    def add_rule(self, rule, priority=0):
        rule.priority = priority
        heapq.heappush(self.rules, (-rule.priority, rule))

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            heapq.heapify(self.rules)

    def clear_rules(self):
        self.rules = []

    def add_packet_processor(self, packet_processor):
        self.packet_processors.append(packet_processor)

    def add_to_allowlist(self, ip_address):
        self.allowlist.append(ip_address)

    def remove_from_allowlist(self, ip_address):
        if ip_address in self.allowlist:
            self.allowlist.remove(ip_address)

    def clear_allowlist(self):
        self.allowlist = []

    def add_to_blocklist(self, ip_address):
        self.blocklist.append(ip_address)

    def remove_from_blocklist(self, ip_address):
        if ip_address in self.blocklist:
            self.blocklist.remove(ip_address)

    def clear_blocklist(self):
        self.blocklist = []

    def disable_firewall(self):
        self.rules = []

    def enable_firewall(self):
        # Reload the rules from the allowlist and blocklist
        self.rules = self._generate_allowlist_rules() + self._generate_blocklist_rules()

    def _generate_allowlist_rules(self):
        allowlist_rules = []
        for ip_address in self.allowlist:
            allow_condition = IPCondition(ip_address)
            allow_action = AllowAction()
            allowlist_rule = FirewallRule(allow_condition, allow_action)
            allowlist_rules.append(allowlist_rule)
        return allowlist_rules

    def _generate_blocklist_rules(self):
        blocklist_rules = []
        for ip_address in self.blocklist:
            block_condition = IPCondition(ip_address)
            block_action = BlockAction()
            blocklist_rule = FirewallRule(block_condition, block_action)
            blocklist_rules.append(blocklist_rule)
        return blocklist_rules

    @staticmethod
    def _process_rule(rule, incoming_packet):
        rule.process(incoming_packet)

    def _process_packet_processors(self, incoming_packet):
        for packet_processor in self.packet_processors:
            packet_processor.process(incoming_packet)

    def process_packet(self, incoming_packet):
        self.packet_count += 1
        self.logger.info("Processing packet: %s", incoming_packet.summary())

        if IP in incoming_packet:
            # Обработка IPv4 пакетов
            matched_rules = self._get_matched_rules(incoming_packet)
            for rule in matched_rules:
                self._process_rule(rule, incoming_packet)
                if rule.action.stops_processing:
                    break
        elif IPv6 in incoming_packet:
            # Обработка IPv6 пакетов
            matched_rules = self._get_matched_rules(incoming_packet)
            for rule in matched_rules:
                self._process_rule(rule, incoming_packet)
                if rule.action.stops_processing:
                    break
        else:
            self.logger.info("Unsupported packet type: %s", incoming_packet.summary())

        self._process_packet_processors(incoming_packet)

    def _get_packet_type(self, packet):
        # Determine packet type based on available layers
        if IP in packet:
            return "IPv4"
        elif IPv6 in packet:
            return "IPv6"
        else:
            return "Unknown"

    def _get_matched_rules(self, incoming_packet):
        matched_rules = []
        for _, rule in self.rules:
            if rule.matches(incoming_packet):
                self.logger.info("Matched rule: %s", rule)
                matched_rules.append(rule)
        return matched_rules

    def start_sniffing(self):
        sniff(prn=self.process_packet)

    def get_packet_count(self):
        return self.packet_count

    def get_packet_types(self):
        return dict(self.packet_types)

    def get_elapsed_time(self):
        return time.time() - self.start_time

    def reset_statistics(self):
        self.packet_count = 0
        self.packet_types = defaultdict(int)
