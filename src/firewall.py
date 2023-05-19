from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import heapq
import pickle
import logging
from collections import defaultdict
import time
from src.condition import IPCondition
from src.action import AllowAction, BlockAction
from src.rule import FirewallRule


class Node:
    def __init__(self, rule):
        self.rule = rule
        self.left = None
        self.right = None


class Firewall:
    def __init__(self):
        self.rules = []
        self.allowlist = []
        self.blocklist = []
        self.packet_processors = []
        self.logger = logging.getLogger("Firewall")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())
        self.cache = {}
        self.rule_index = {}
        self._rule_cache = {}
        self.root = None

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
        node = Node(rule)
        if self.root is None:
            self.root = node
        else:
            self._insert_node(self.root, node)
        self._update_rule_index(rule)
        self.cache.clear()

    def _insert_node(self, root, node):
        if node.rule.priority > root.rule.priority:
            if root.right is None:
                root.right = node
            else:
                self._insert_node(root.right, node)
        else:
            if root.left is None:
                root.left = node
            else:
                self._insert_node(root.left, node)

    def _update_rule_index(self, rule):
        packet_characteristics = self._get_packet_characteristics(rule.condition)
        for characteristic in packet_characteristics:
            if characteristic not in self.rule_index:
                self.rule_index[characteristic] = []
            self.rule_index[characteristic].append(rule)

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            heapq.heapify(self.rules)
            self.cache.clear()

    def _get_packet_characteristics(self, packet):
        characteristics = {}

        if isinstance(packet, IP):
            characteristics['source_ip'] = packet.src
            characteristics['destination_ip'] = packet.dst
            characteristics['source_port'] = packet.sport
            characteristics['destination_port'] = packet.dport
            characteristics['protocol'] = packet.proto
        elif isinstance(packet, IPv6):
            characteristics['source_ip'] = packet.src
            characteristics['destination_ip'] = packet.dst
            characteristics['source_port'] = packet.sport
            characteristics['destination_port'] = packet.dport
            characteristics['protocol'] = packet.nh

        return characteristics

    def _add_rule_to_index(self, condition, action):
        if condition in self.rule_index:
            self.rule_index[condition].append(action)
        else:
            self.rule_index[condition] = [action]

    def _remove_rule_from_index(self, rule):
        packet_characteristics = self._get_packet_characteristics(rule.condition)
        for characteristic in packet_characteristics:
            if characteristic in self.rule_index:
                self.rule_index[characteristic].remove(rule)

    def clear_rules(self):
        self.rules = []
        self.rule_index = {}

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
        self.root = None
        self._add_rules_from_lists()
        self.cache.clear()
        self.rules = self._generate_allowlist_rules() + self._generate_blocklist_rules()
        self._rebuild_rule_index()  # Rebuild rule index with updated rules

    def _add_rules_from_lists(self):
        self._add_rules_from_list(self.allowlist, AllowAction())
        self._add_rules_from_list(self.blocklist, BlockAction())

    def _add_rules_from_list(self, ip_list, action):
        for ip_address in ip_list:
            condition = IPCondition(ip_address)
            rule = FirewallRule(condition, action)
            self.add_rule(rule)

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

    def _rebuild_rule_index(self):
        self.rule_index = {}
        for rule in self.rules:
            self._update_rule_index(rule)

    def _process_rule(self, rule, incoming_packet):
        rule.process(incoming_packet)

    def _process_packet_processors(self, incoming_packet):
        for packet_processor in self.packet_processors:
            packet_processor.process(incoming_packet)

    def process_packet(self, incoming_packet):
        self.packet_count += 1
        self.logger.info("Processing packet: %s", incoming_packet.summary())

        if IP in incoming_packet:
            # Handling IPv4 packets
            packet_type = self._get_packet_type(incoming_packet)
            matched_rules = self._get_matched_rules(incoming_packet, packet_type)

            for rule in matched_rules:
                self._process_rule(rule, incoming_packet)
                if rule.action.stops_processing:
                    break
        elif IPv6 in incoming_packet:
            # Handling IPv6 Packets
            packet_type = self._get_packet_type(incoming_packet)
            matched_rules = self._get_matched_rules(incoming_packet, packet_type)

            for rule in matched_rules:
                self._process_rule(rule, incoming_packet)
                if rule.action.stops_processing:
                    break
        else:
            self.logger.info("Unsupported packet type: %s", incoming_packet.summary())

        self._process_packet_processors(incoming_packet)

    def _get_matched_rules(self, incoming_packet, packet_type):
        matched_rules = []
        if packet_type in self._rule_cache:
            # If the packet type is cached, retrieve the matched rules from the cache
            matched_rules = self._rule_cache[packet_type]
        else:
            # If the packet type is not cached, find the matched rules and cache them
            self._get_matched_rules_recursive(self.root, incoming_packet, packet_type, matched_rules)
            self._rule_cache[packet_type] = matched_rules

        return matched_rules

    def _get_matched_rules_recursive(self, node, packet, packet_type, matched_rules):
        if node is None:
            return

        if node.rule is not None and node.rule.matches(packet):
            matched_rules.append(node.rule)

        if packet_type == "IPv4" and node.left is not None:
            self._get_matched_rules_recursive(node.left, packet, packet_type, matched_rules)
            self._get_matched_rules_recursive(node.right, packet, packet_type, matched_rules)
        elif packet_type == "IPv6" and node.right is not None:
            self._get_matched_rules_recursive(node.right, packet, packet_type, matched_rules)
            self._get_matched_rules_recursive(node.left, packet, packet_type, matched_rules)

    def _get_packet_type(self, packet):
        # Determine packet type based on available layers
        if IP in packet:
            return "IPv4"
        elif IPv6 in packet:
            return "IPv6"
        else:
            return "Unknown"

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
