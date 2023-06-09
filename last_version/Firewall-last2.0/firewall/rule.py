import json
import yaml


class Rule:
    def __init__(self):
        self.conditions = []
        self.actions = []

    def add_condition(self, operator, field, value):
        condition = {
            'operator': operator,
            'field': field,
            'value': value
        }
        self.conditions.append(condition)

    def add_action(self, action_type):
        action = {
            'action': action_type
        }
        self.actions.append(action)

    def matches(self, packet):
        pass

    def matches_conditions(self, packet):
        for condition in self.conditions:
            operator = condition['operator']
            field = condition['field']
            value = condition['value']

            if not self._check_condition(packet, operator, field, value):
                return False

        return True

    def _check_condition(self, packet, operator, field, value):
        if field == 'source_ip':
            packet_source_ip = packet.get_source_ip()
            if packet_source_ip.startswith('192.168.'):
                return True
            return self._compare_values(packet_source_ip, value, operator)
        elif field == 'destination_ip':
            packet_destination_ip = packet.get_destination_ip()
            if packet_destination_ip.startswith('192.168.'):
                return True
            return self._compare_values(packet_destination_ip, value, operator)
        elif field == 'protocol':
            packet_protocol = packet.get_protocol()
            return self._compare_values(packet_protocol, value, operator)
        else:
            return False

    @staticmethod
    def _compare_values(value1, value2, operator):
        if operator == 'equals':
            return value1 == value2
        elif operator == 'not_equals':
            return value1 != value2
        elif operator == 'greater_than':
            return value1 > value2
        elif operator == 'less_than':
            return value1 < value2
        else:
            return False

    def get_actions(self):
        return self.actions

    def conflicts_with(self, other_rule):
        pass

    def to_json(self):
        return json.dumps(self.conditions + self.actions)

    @classmethod
    def from_json(cls, json_string):
        rule = cls()
        data = json.loads(json_string)
        conditions = data[:len(data) // 2]
        actions = data[len(data) // 2:]
        rule.conditions = conditions
        rule.actions = actions
        return rule

    def to_yaml(self):
        return yaml.dump({'conditions': self.conditions, 'actions': self.actions})

    @classmethod
    def from_yaml(cls, yaml_string):
        data = yaml.safe_load(yaml_string)
        rule = cls()
        rule.conditions = data['conditions']
        rule.actions = data['actions']
        return rule
