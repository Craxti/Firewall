from abc import ABC, abstractmethod
from datetime import datetime


class Condition(ABC):
    @abstractmethod
    def matches(self, packet):
        raise NotImplementedError("matches() method must be implemented in subclasses.")

    def __and__(self, other):
        return AndCondition(self, other)

    def __or__(self, other):
        return OrCondition(self, other)


class CompositeCondition(Condition):
    def __init__(self, conditions):
        self.conditions = conditions

    @abstractmethod
    def matches(self, packet):
        pass


class Action(ABC):
    @abstractmethod
    def process(self, packet):
        raise NotImplementedError("process() method must be implemented in subclasses.")

    def __and__(self, other):
        return AndAction(self, other)

    def __or__(self, other):
        return OrAction(self, other)


class FirewallRule:
    def __init__(self, condition, action,  priority=0):
        self.condition = condition
        self.action = action
        self.priority = priority
        self.time_ranges = []

    def __lt__(self, other):
        return self.priority < other.priority

    def __eq__(self, other):
        return self.priority == other.priority

    def __ne__(self, other):
        return self.priority != other.priority

    def add_time_range(self, start_time, end_time):
        self.time_ranges.append((start_time, end_time))

    def matches(self, packet):
        if self.time_ranges:
            current_time = datetime.now().time()
            for start_time, end_time in self.time_ranges:
                if start_time <= current_time <= end_time:
                    break
            else:
                return False

        return self.condition.matches(packet)

    def process(self, packet):
        self.action.process(packet)


class AndCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    def matches(self, packet):
        return self.condition1.matches(packet) and self.condition2.matches(packet)


class OrCondition(Condition):
    def __init__(self, condition1, condition2):
        self.condition1 = condition1
        self.condition2 = condition2

    def matches(self, packet):
        return self.condition1.matches(packet) or self.condition2.matches(packet)


class NotCondition(Condition):
    def __init__(self, condition):
        self.condition = condition

    def matches(self, packet):
        return not self.condition.matches(packet)


class AndAction(Action):
    def __init__(self, action1, action2):
        self.action1 = action1
        self.action2 = action2

    def process(self, packet):
        self.action1.process(packet)
        self.action2.process(packet)


class OrAction(Action):
    def __init__(self, action1, action2):
        self.action1 = action1
        self.action2 = action2

    def process(self, packet):
        self.action1.process(packet)
        self.action2.process(packet)


# Enhanced conditions

class IPCondition(Condition):
    def __init__(self, ip_address):
        self.ip_address = ip_address

    def matches(self, packet):
        return packet.source_ip == self.ip_address or packet.destination_ip == self.ip_address


class PortCondition(Condition):
    def __init__(self, port):
        self.port = port

    def matches(self, packet):
        return packet.source_port == self.port or packet.destination_port == self.port


class ProtocolCondition(Condition):
    def __init__(self, protocol):
        self.protocol = protocol

    def matches(self, packet):
        return packet.protocol == self.protocol


class PayloadContentCondition(Condition):
    def __init__(self, content):
        self.content = content

    def matches(self, packet):
        return self.content in packet.payload.decode('utf-8')


# Enhanced actions

class ModifyPacketAction(Action):
    def __init__(self, field, value):
        self.field = field
        self.value = value

    def process(self, packet):
        setattr(packet, self.field, self.value)


class RedirectPacketAction(Action):
    def __init__(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def process(self, packet):
        packet.destination_ip = self.dst_ip
        packet.destination_port = self.dst_port
        packet.send()


class LogPacketAction(Action):
    def __init__(self, log_file):
        self.log_file = log_file

    def process(self, packet):
        with open(self.log_file, "a") as f:
            f.write(f"Logged packet: {packet.summary()}\n")


class DropPacketAction(Action):
    def process(self, packet):
        packet.drop()


class AllowPacketAction(Action):
    def process(self, packet):
        packet.accept()


class CombinedAction(Action):
    def __init__(self, actions):
        self.actions = actions

    def process(self, packet):
        for action in self.actions:
            action.process(packet)


class Rule:
    def __init__(self, condition, action):
        self.condition = condition
        self.action = action

    def matches(self, packet):
        return self.condition.matches(packet)

    def process(self, packet):
        self.action.process(packet)

