from copy import deepcopy
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

        self.client_seq = 0
        self.server_seq = 0
        self.client_ack = 0
        self.server_ack = 0

        self.src_ip = None
        self.dst_ip = None
        self.src_prt = None
        self.dst_prt = None
        self.src_address_fam = None
        self.dst_address_fam = None

    def add_source(self, sock: socket.socket):
        self.src_ip = sock.getpeername()[0]
        self.src_prt = sock.getpeername()[1]
        self.src_address_fam = self.get_address_family(sock.getpeername()[0])

    def add_destination(self, sock: socket.socket):
        self.dst_ip = sock.getpeername()[0]
        self.dst_prt = sock.getpeername()[1]
        self.dst_address_fam = self.get_address_family(sock.getpeername()[0])

    def add_packet(self, data: bytes, is_client=True):
        if len(data) == 0:
            return
        ts = datetime.datetime.now().timestamp()
        packet, ack = self.convert_packet(data, is_client)
        if packet:
            self.packets.append((ts, packet))
        if ack:
            self.packets.append((ts, ack))
    
    def add_three_way_handshake(self):

        # 1. SYN: Client -> Server
        self.client_seq = 1000  # Zufällige SEQ-Nummer des Clients
        syn = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, seq=self.client_seq, flags=dpkt.tcp.TH_SYN)
        ip_syn = dpkt.ip.IP(src=socket.inet_pton(self.src_address_fam, self.src_ip), dst=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_syn.data = syn

        eth_syn = dpkt.ethernet.Ethernet(
            src=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            dst=b'\x00\x40\x6c\xac\xd0',      # Dummy Ziel-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_syn.data = ip_syn
        self.packets.append((datetime.datetime.now().timestamp(), eth_syn))
        self.client_seq += 1

        # 2. SYN-ACK: Server -> Client
        self.server_seq = 2000  # Zufällige SEQ-Nummer des Servers
        self.server_ack = self.client_seq
        syn_ack = dpkt.tcp.TCP(sport=self.dst_prt, dport=self.src_prt, seq=self.server_seq, ack=self.server_ack, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        ip_syn_ack = dpkt.ip.IP(src=socket.inet_pton(self.dst_address_fam, self.dst_ip), dst=socket.inet_pton(self.src_address_fam, self.src_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_syn_ack.data = syn_ack

        eth_syn_ack = dpkt.ethernet.Ethernet(
            src=b'\x00\x40\x6c\xac\xd0',  # Dummy Ziel-MAC-Adresse
            dst=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_syn_ack.data = ip_syn_ack
        self.packets.append((datetime.datetime.now().timestamp(), eth_syn_ack))
        self.server_seq += 1

        # 3. ACK: Client -> Server (mit möglichen ersten Daten)
        self.client_ack = self.server_seq  # ACK vom Client auf die Server SEQ
        ack = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, ack=self.client_ack, flags=dpkt.tcp.TH_ACK)
        ip_ack = dpkt.ip.IP(src=socket.inet_pton(self.src_address_fam, self.src_ip), dst=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_ack.data = ack

        eth_ack = dpkt.ethernet.Ethernet(
            src=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            dst=b'\x00\x40\x6c\xac\xd0',  # Dummy Ziel-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_ack.data = ip_ack
        self.packets.append((datetime.datetime.now().timestamp(), eth_ack))

    def add_teardown_handshake(self):
        """Fügt den TCP Teardown Handshake zur Verbindung hinzu."""

        fin = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, seq=self.client_seq, ack=0, flags=dpkt.tcp.TH_FIN)
        ip_fin = dpkt.ip.IP(src=socket.inet_pton(self.src_address_fam, self.src_ip), dst=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_fin.data = fin

        eth_fin = dpkt.ethernet.Ethernet(
            src=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            dst=b'\x00\x40\x6c\xac\xd0',      # Dummy Ziel-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_fin.data = ip_fin
        self.packets.append((datetime.datetime.now().timestamp(), eth_fin))

        # 2. ACK: Server -> Client
        self.server_ack = self.client_seq + 1
        ack = dpkt.tcp.TCP(sport=self.dst_prt, dport=self.src_prt, seq=0, ack=self.server_ack, flags=dpkt.tcp.TH_ACK)
        ip_ack = dpkt.ip.IP(src=socket.inet_pton(self.dst_address_fam, self.dst_ip), dst=socket.inet_pton(self.src_address_fam, self.src_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_ack.data = ack

        eth_ack = dpkt.ethernet.Ethernet(
            src=b'\x00\x40\x6c\xac\xd0',  # Dummy Ziel-MAC-Adresse
            dst=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_ack.data = ip_ack
        self.packets.append((datetime.datetime.now().timestamp(), eth_ack))

        # 3. FIN: Server -> Client
        fin_server = dpkt.tcp.TCP(sport=self.dst_prt, dport=self.src_prt, seq=self.server_seq, ack=0, flags=dpkt.tcp.TH_FIN)
        ip_fin_server = dpkt.ip.IP(src=socket.inet_pton(self.dst_address_fam, self.dst_ip), dst=socket.inet_pton(self.src_address_fam, self.src_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_fin_server.data = fin_server

        eth_fin_server = dpkt.ethernet.Ethernet(
            src=b'\x00\x40\x6c\xac\xd0',  # Dummy Ziel-MAC-Adresse
            dst=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_fin_server.data = ip_fin_server
        self.packets.append((datetime.datetime.now().timestamp(), eth_fin_server))

        # 4. ACK: Client -> Server
        self.client_ack = self.server_seq + 1
        ack_client = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, seq=0, ack=self.client_ack, flags=dpkt.tcp.TH_ACK)
        ip_ack_client = dpkt.ip.IP(src=socket.inet_pton(self.src_address_fam, self.src_ip), dst=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_ack_client.data = ack_client

        eth_ack_client = dpkt.ethernet.Ethernet(
            src=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            dst=b'\x00\x40\x6c\xac\xd0',      # Dummy Ziel-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )
        eth_ack_client.data = ip_ack_client
        self.packets.append((datetime.datetime.now().timestamp(), eth_ack_client))

    def convert_packet(self, data: bytes, is_client=True):

        ether_header_client = dpkt.ethernet.Ethernet(
            src=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            dst=b'\x00\x40\x6c\xac\xd0',      # Dummy Ziel-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )

        ether_header_server = dpkt.ethernet.Ethernet(
            src=b'\x00\x40\x6c\xac\xd0',      # Dummy Ziel-MAC-Adresse
            dst=b'\x45\x00\x1f\x6e\x00\x00',  # Dummy Quell-MAC-Adresse
            type=dpkt.ethernet.ETH_TYPE_IP
        )

        
        ip_proto_client = dpkt.ip.IP(src=socket.inet_pton(self.src_address_fam, self.src_ip), dst=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)
        ip_proto_server = dpkt.ip.IP(dst=socket.inet_pton(self.src_address_fam, self.src_ip), src=socket.inet_pton(self.dst_address_fam, self.dst_ip), p=dpkt.ip.IP_PROTO_TCP)

        
        if is_client:
            # Neues TCP-Paket von Client -> Server
            tcp = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, seq=self.client_seq, ack=self.client_ack, flags=0)
            tcp.data = deepcopy(data)
            ip_proto_client.data = tcp
            ether_header_client.data = ip_proto_client

            self.client_seq += len(data)  # Inkrementiere die SEQ-Nummer basierend auf den gesendeten Daten
            self.server_ack = self.client_seq # Server erwartet die nächste SEQ-Nummer vom Client

            # SERVER ACK
            tcp_server = dpkt.tcp.TCP(sport=self.dst_prt, dport=self.src_prt, seq=self.server_seq, ack=self.server_ack, flags=dpkt.tcp.TH_ACK)
            ip_proto_server.data = tcp_server
            ether_header_server.data = ip_proto_server

            return ether_header_client, ether_header_server

        else:
            # Neues TCP-Paket von Server -> Client
            tcp = dpkt.tcp.TCP(sport=self.dst_prt, dport=self.src_prt, seq=self.server_seq, ack=self.server_ack, flags=0)
            tcp.data = deepcopy(data)
            ip_proto_server.data = tcp
            ether_header_server.data = ip_proto_server

            self.server_seq += len(data)  # Inkrementiere die SEQ-Nummer basierend auf den gesendeten Daten
            self.client_ack = self.server_seq  # Client erwartet die nächste SEQ-Nummer vom Server

            # CLIENT ACK
            tcp_client = dpkt.tcp.TCP(sport=self.src_prt, dport=self.dst_prt, seq=self.client_seq, ack=self.client_ack, flags=dpkt.tcp.TH_ACK)
            ip_proto_client.data = tcp_client
            ether_header_client.data = ip_proto_client

            return ether_header_server, ether_header_client

    def export(self):
        try:
            if len(self.packets) == 0:
                return        
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            directory = os.getenv('PCAP_DIR_PATH', './')
            os.makedirs(directory, exist_ok=True) 
            filename = f"{self.filename}_{timestamp}.pcap"
            export_path = os.getenv('PCAP_EXPORT_PATH')
            os.makedirs(export_path, exist_ok=True)
            full_path = os.path.join(export_path, filename)
            with open(full_path, 'wb') as f:
                writer = dpkt.pcap.Writer(f)  # Ethernet Linktype
                for ts, data in self.packets:
                    writer.writepkt(data, ts)
            self.packets = []
        except Exception as e:
            print(f"Exception in pcap exporter: {str(e)}")

    def get_address_family(self, host):
        try:
            result = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return result[0][0]
        except socket.gaierror as e:
            print(f"Error resolving host: {e}")
            return None
