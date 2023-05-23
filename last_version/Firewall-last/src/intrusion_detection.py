import logging
from scapy.all import sniff
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.sendrecv import send
import yaml
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import threading
import time


class IntrusionDetection:
    def __init__(self):
        self.logger = logging.getLogger("IntrusionDetection")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logging.StreamHandler())
        self.known_threats = []
        self.machine_learning_model = None
        self.training_data = []
        self.training_labels = []
        self.training_lock = threading.Lock()
        self.update_interval = 60  # Update the model every 60 seconds

    def load_config(self):
        with open("config.yaml", "r") as config_file:
            config = yaml.safe_load(config_file)
            self.known_threats = config.get("known_threats", [])

    def process_packet(self, packet):
        self.logger.info("Analyzing packet: %s", packet.summary())

        if self.detect_known_threat(packet):
            return

        if self.machine_learning_model and self.detect_unknown_threat(packet):
            return

        self.logger.info("No threat detected.")

    def detect_known_threat(self, packet):
        for threat in self.known_threats:
            if self.match_threat(threat, packet):
                self.logger.warning("Detected known threat: %s", threat["description"])
                return True
        return False

    def detect_unknown_threat(self, packet):
        packet_summary = packet.summary()
        prediction = self.machine_learning_model.predict([packet_summary])
        if prediction[0] == 1:
            self.logger.warning("Detected unknown threat using machine learning.")
            return True
        return False

    def match_threat(self, threat, packet):
        if IP in packet:
            ip_address = packet[IP].src
            protocol = packet[IP].proto
            if ip_address == threat["ip_address"] and protocol == threat["protocol"]:
                if protocol == "TCP":
                    if TCP in packet and packet[TCP].dport == threat["port"]:
                        return True
                elif protocol == "UDP":
                    if UDP in packet and packet[UDP].dport == threat["port"]:
                        return True
                else:
                    return True
        return False

    def block_threat(self, packet):
        icmp_error = ICMP(type=3, code=1)  # Destination Unreachable - Host Unreachable
        response_packet = IP(src=packet.dst, dst=packet.src) / icmp_error / packet
        send(response_packet, iface="eth0")

    def train_machine_learning_model(self):
        vectorizer = CountVectorizer()
        X = vectorizer.fit_transform(self.training_data)
        y = self.training_labels
        self.machine_learning_model = MultinomialNB()
        self.machine_learning_model.fit(X, y)

    def update_machine_learning_model(self):
        while True:
            self.training_lock.acquire()
            if self.training_data and self.training_labels:
                self.logger.info("Updating machine learning model...")
                self.train_machine_learning_model()
                self.logger.info("Machine learning model updated.")
                self.training_data = []
                self.training_labels = []
            self.training_lock.release()
            time.sleep(self.update_interval)

    def start_detection(self):
        self.load_config()
        self.logger.info("Starting intrusion detection...")

        # Start the thread for updating the machine learning model
        update_thread = threading.Thread(target=self.update_machine_learning_model)
        update_thread.daemon = True
        update_thread.start()

        # Start sniffing packets and process them
        sniff(prn=self.process_packet)

    def add_training_data(self, packet_summary, label):
        self.training_lock.acquire()
        self.training_data.append(packet_summary)
        self.training_labels.append(label)
        self.training_lock.release()


if __name__ == "__main__":
    intrusion_detection = IntrusionDetection()
    intrusion_detection.start_detection()
