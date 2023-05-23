from firewall.rule import Rule
import yaml
import json


def parse_rules(file_path):
    file_extension = file_path.split('.')[-1].lower()

    if file_extension == 'yaml' or file_extension == 'yml':
        try:
            with open(file_path, 'r') as file:
                rules_data = yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error loading YAML file: {e}")
    elif file_extension == 'json':
        try:
            with open(file_path, 'r') as file:
                rules_data = json.load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error loading JSON file: {e}")
    else:
        raise ValueError(f"Unsupported file format: {file_extension}")

    rules = []

    if not isinstance(rules_data, list):
        raise ValueError("Invalid rule data format")

    for rule_data in rules_data:
        if not isinstance(rule_data, dict):
            raise ValueError("Invalid rule data format")

        if 'conditions' not in rule_data or 'actions' not in rule_data:
            raise ValueError("Invalid rule data format")

        conditions = rule_data['conditions']
        actions = rule_data['actions']

        if not isinstance(conditions, list) or not isinstance(actions, list):
            raise ValueError("Invalid rule data format")

        rule = Rule()

        for condition in conditions:
            if not isinstance(condition, dict) or 'operator' not in condition or 'field' not in condition or 'value' not in condition:
                raise ValueError("Invalid condition data format")

            operator = condition['operator']
            field = condition['field']
            value = condition['value']

            rule.add_condition(operator, field, value)

        for action in actions:
            if not isinstance(action, dict) or 'action' not in action:
                raise ValueError("Invalid action data format")

            action_type = action['action']
            rule.add_action(action_type)

        rules.append(rule)

    return rules
