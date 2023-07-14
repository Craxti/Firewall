import logging
import uuid


class ConnectionTracker:
    def __init__(self):
        self.connections = []
        self.statistics = {}
        self.logger = logging.getLogger('firewall')

    def process_packet(self, packet):
        source_ip = packet.get_source_ip()
        destination_ip = packet.get_destination_ip()

        if self._is_connection_exists(source_ip, destination_ip):
            self._update_connection(source_ip, destination_ip)
        else:
            self._create_connection(source_ip, destination_ip)

    def _is_connection_exists(self, source_ip, destination_ip):
        for connection in self.connections:
            if connection['source_ip'] == source_ip and connection['destination_ip'] == destination_ip:
                return True
        return False

    def _update_connection(self, source_ip, destination_ip):
        for connection in self.connections:
            if connection['source_ip'] == source_ip and connection['destination_ip'] == destination_ip:
                connection['packet_count'] += 1

    def _create_connection(self, source_ip, destination_ip):
        connection = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'packet_count': 1
        }
        self.connections.append(connection)

    def get_connections(self):
        return self.connections

    def add_connection(self, connection):
        self.connections[connection.id] = connection
        self.statistics['total_connections'] += 1
        self.logger.info(f"Added connection: {connection.id}")

    def remove_connection(self, connection_id):
        connection = self.connections[connection_id]
        if connection:
            del self.connections[connection_id]
            self.statistics['total_connections'] -= 1
            self.logger.info(f"Removed connection: {connection_id}")


class Connection:
    def __init__(self):
        self.id = self._get_connection_id()
        self.state = self._get_initial_state()
        self.data_transferred = 0

        self.logger = logging.getLogger("Connection")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        file_handler = logging.FileHandler("logs/connection.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _get_connection_id(self):
        return str(uuid.uuid4())

    def _get_initial_state(self):
        return "ESTABLISHED"

    def update_state(self, state):
        if state in ['ESTABLISHED', 'CLOSED', 'WAITING']:
            self.state = state
            self.logger.info(f"Connection state updated: {self.id}, State: {self.state}")
        else:
            raise ValueError("Invalid connection state.")

    def process_data(self, data):
        data_size = len(data)
        self.data_transferred += data_size
        self.logger.info(f"Data transferred for connection {self.id}: {self.data_transferred} bytes")
