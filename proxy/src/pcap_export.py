import datetime
import dpkt
import os
from dotenv import load_dotenv

load_dotenv()

class PCAPExporter:
    def __init__(self, service_name: str):
        self.packets = []
        self.filename = service_name

    def add_packet(self, data: bytes):
        ts = datetime.datetime.now().timestamp()
        self.packets.append((ts, data))
        if len(self.packets) == int(os.getenv('PCAP_MAX_PACKETS')):
            self.export()

    def export(self):
        timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
        filename = f"{self.filename}_{timestamp}.pcap"
        with open(filename, 'wb') as f:
            writer = dpkt.pcap.Writer(f)
            for ts, data in self.packets:
                writer.writepkt(data, ts)
        self.packets = []