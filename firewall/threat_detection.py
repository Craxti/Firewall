import tensorflow as tf
import logging
from firewall.packet import Packet


class ThreatDetector:
    def __init__(self, rules):
        self.rules = rules

        self.logger = logging.getLogger("ThreatDetector")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        file_handler = logging.FileHandler("logs/threat_detection.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def detect_threats(self, packets):
        if isinstance(packets, Packet):
            packets = [packets]

        threats = []
        for packet in packets:
            matched_rules = [rule for rule in self.rules if rule.matches(packet)]
            if matched_rules:
                threat_info = {
                    'packet': packet,
                    'matched_rules': matched_rules
                }
                threats.append(threat_info)
                self.logger.warning(f"Threat detected: {threat_info}")

        return threats

    def add_rule(self, rule):
        self.rules.append(rule)
        self.logger.info(f"Rule added: {rule}")

    def remove_rule(self, rule):
        self.rules.remove(rule)
        self.logger.info(f"Rule removed: {rule}")


class Rule:
    def __init__(self, name):
        self.name = name

    def matches(self, packet):
        raise NotImplementedError("Subclasses must implement matches() method.")


class DDosRule(Rule):
    def __init__(self, name, threshold):
        super().__init__(name)
        self.threshold = threshold
        self.packet_count = 0

    def matches(self, packet):
        if self.packet_count >= self.threshold:
            return True

        self.packet_count += 1
        return False


class IntrusionRule(Rule):
    def __init__(self, name, pattern):
        super().__init__(name)
        self.pattern = pattern

    def matches(self, packet):
        if self.pattern in packet.payload:
            return True

        return False


class MachineLearningRule(Rule):
    def __init__(self, name, model_path):
        super().__init__(name)
        self.model = tf.keras.models.load_model(model_path)

    def matches(self, packet):
        processed_data = self.preprocess_packet(packet)

        if processed_data is None:
            return False

        prediction = self.model.predict(processed_data)

        threshold = 0.5
        if prediction > threshold:
            return True
        else:
            return False

    @staticmethod
    def preprocess_packet(packet):
        if packet.payload is None:
            return None

        processed_data = packet.payload

        processed_data = tf.convert_to_tensor(processed_data, dtype=tf.float32)

        processed_data = tf.keras.utils.normalize(processed_data)

        processed_data = tf.reshape(processed_data, shape=(1, -1))

        return processed_data


class StatisticalAnalysisRule(Rule):
    def __init__(self, name, analysis_algorithm):
        super().__init__(name)
        self.analysis_algorithm = analysis_algorithm

    def matches(self, packet):
        pass
