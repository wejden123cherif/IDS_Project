from datetime import datetime

class SecurityEvent:
    def __init__(self, category, severity, message, src_ip=None, src_mac=None):
        self.timestamp = datetime.now()
        self.category = category
        self.severity = severity
        self.message = message
        self.src_ip = src_ip
        self.src_mac = src_mac

    def __str__(self):
        return (
            f"[{self.timestamp}] "
            f"[{self.severity}] "
            f"{self.category}: {self.message} "
            f"(IP={self.src_ip}, MAC={self.src_mac})"
        )
