class PacketFilter:
    def __init__(self, filters):
        self.filters = filters

    def apply_filters(self, packets):
        filtered_packets = []

        for packet in packets:
            if self._packet_matches_filters(packet):
                filtered_packets.append(packet)

        return filtered_packets

    def add_filter(self, filter_condition):
        self.filters.append(filter_condition)

    def _packet_matches_filters(self, packet):
        if not self.filters:
            return True

        if len(self.filters) == 1:
            return self.filters[0](packet)

        logical_operator = self.filters[0]
        result = self.filters[1](packet)

        for i in range(2, len(self.filters), 2):
            if logical_operator == "AND":
                result = result and self.filters[i](packet)
            elif logical_operator == "OR":
                result = result or self.filters[i](packet)

            logical_operator = self.filters[i + 1]

        return result
