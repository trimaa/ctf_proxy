import datetime
import socket
import dpkt
import os
from dotenv import load_dotenv

load_dotenv()

class PCAPExporter:
    def __init__(self, service_name: str):
        self.packets = []
        self.filename = service_name

    def add_packet(self, data: bytes, sock: socket.socket):
        ts = datetime.datetime.now().timestamp()
        self.packets.append((ts, self.convert_packet(data, sock)))
        #if len(self.packets) == int(os.getenv('PCAP_MAX_PACKETS')):
            #self.export()

    def convert_packet(self, data: bytes, sock: socket.socket):
        dst_ip = sock.getsockname()[0]
        dst_prt = sock.getsockname()[1]
        src_ip = sock.getpeername()[0]
        src_prt = sock.getpeername()[1]
        ip_proto = dpkt.ip.IP(src=socket.inet_pton(socket.AF_INET, src_ip), dst=socket.inet_pton(socket.AF_INET, dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        #new_tcp = dpkt.tcp.TCP(sport=src_prt, dport=dst_prt, seq=client_seq, ack=client_ack, flags=0)

    def export(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.filename}_{timestamp}.pcap"
        with open(filename, 'wb') as f:
            writer = dpkt.pcap.Writer(f)
            for ts, data in self.packets:
                writer.writepkt(data, ts)
        self.packets = []
