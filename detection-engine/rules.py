"""Rule-based threat detection for known attack patterns."""


class RuleEngine:
    """Evaluates network features against known threat signatures."""

    def __init__(self):
        self.rules = [
            ("SYN_FLOOD", self._syn_flood),
            ("PORT_SCAN", self._port_scan),
            ("LARGE_PAYLOAD", self._large_payload),
            ("HIGH_FREQUENCY", self._high_frequency),
        ]

    def evaluate(self, features):
        """Return list of triggered rule names."""
        triggered = []
        for name, check in self.rules:
            if check(features):
                triggered.append(name)
        return triggered

    def _syn_flood(self, f):
        return f["syn_ratio"] > 0.8 and f["packet_rate"] > 50

    def _port_scan(self, f):
        return f["unique_dst_ports"] > 20

    def _large_payload(self, f):
        return f["packet_size"] > 10_000

    def _high_frequency(self, f):
        return f["packet_rate"] > 200
