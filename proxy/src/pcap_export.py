from copy import deepcopy
import datetime
import socket
import dpkt
import os
from dotenv import load_dotenv

from src import utils

load_dotenv()

class PCAPExporter:
    def __init__(self, service_name: str):
        self.packets = []
        self.filename = service_name
        self.seq = 1
        self.ack = 1

    def add_packet(self, data: bytes, sock: socket.socket):
        if len(data) == 0:
            return
        ts = datetime.datetime.now().timestamp()
        self.packets.append((ts, self.convert_packet(data, sock)))

    def convert_packet(self, data: bytes, sock: socket.socket):
        dst_ip = sock.getsockname()[0]
        dst_address_fam = self.get_address_family(sock.getsockname()[0])
        dst_prt = sock.getsockname()[1]
        src_ip = sock.getpeername()[0]
        src_address_fam = self.get_address_family(sock.getpeername()[0])
        src_prt = sock.getpeername()[1]
        ip_proto = dpkt.ip.IP(src=socket.inet_pton(src_address_fam, src_ip), dst=socket.inet_pton(dst_address_fam, dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        new_tcp = dpkt.tcp.TCP(sport=src_prt, dport=dst_prt, seq=self.seq, ack=self.ack, flags=0)
        new_tcp.data = deepcopy(data)
        ip_proto.data = new_tcp
        return ip_proto

    def export(self):
        try:
            if len(self.packets) == 0:
                return        
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.filename}_{timestamp}.pcap"
            with open(filename, 'wb') as f:
                writer = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_RAW)
                for ts, data in self.packets:
                    writer.writepkt(data, ts)
            self.packets = []
        except Exception as e:
            print(f"Exception in pcap exporter: {str(e)}")
    
    def get_address_family(self,host):
            try:
                result = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
                return result[0][0]
            except socket.gaierror as e:
                print(f"Error resolving host: {e}")
                return None   
