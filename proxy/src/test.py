import dpkt
import socket
from copy import deepcopy


def create_full_packets(server_ip, client_ip, server_port, client_port, pcap):
    ip_proto_client = dpkt.ip.IP(src=socket.inet_pton(socket.AF_INET, client_ip), dst=socket.inet_pton(socket.AF_INET, server_ip), p=dpkt.ip.IP_PROTO_TCP)
    ip_proto_server = dpkt.ip.IP(dst=socket.inet_pton(socket.AF_INET, client_ip), src=socket.inet_pton(socket.AF_INET, server_ip), p=dpkt.ip.IP_PROTO_TCP)
    packets = []
    # TCP Handshake
    syn = dpkt.tcp.TCP(sport=client_port, dport=server_port, seq=0, ack=0, flags=dpkt.tcp.TH_SYN)
    ip_syn = deepcopy(ip_proto_client)
    ip_syn.data = syn
    packets.append(ip_syn)

    syn_ack = dpkt.tcp.TCP(seq=0, sport=server_port, dport=client_port, flags=dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK, ack=1)
    ip_syn_ack = deepcopy(ip_proto_server)
    ip_syn_ack.data = syn_ack
    packets.append(ip_syn_ack)

    ack = dpkt.tcp.TCP(seq=1, sport=client_port, dport=server_port, flags=dpkt.tcp.TH_ACK, ack=1)
    ip_ack = deepcopy(ip_proto_client)
    ip_ack.data = ack
    packets.append(ip_ack)

    client_ack = 1
    server_ack = 1
    client_seq = 1
    server_seq = 1
    for _, buf in pcap:
        tcp = dpkt.ethernet.Ethernet(buf).data.data
        # ignore non-tcp and empty packets
        if not isinstance(tcp, dpkt.tcp.TCP) or len(tcp.data) == 0:
            continue
        data = tcp.data
        # Check if this is a client->server packet
        if tcp.dport == server_port:
            new_tcp = dpkt.tcp.TCP(sport=client_port, dport=server_port, seq=client_seq, ack=client_ack, flags=0)
            client_seq += len(data)
            new_tcp.data = deepcopy(data)
            new_ip = deepcopy(ip_proto_client)
            new_ip.data = new_tcp
            packets.append(new_ip)

            # Create corresponding ACK
            server_ack = client_seq
            new_tcp = dpkt.tcp.TCP(dport=client_port, sport=server_port, seq=server_seq, ack=server_ack, flags=dpkt.tcp.TH_ACK)
            new_ip = deepcopy(ip_proto_server)
            new_ip.data = new_tcp
            packets.append(new_ip)
        else:
            new_tcp = dpkt.tcp.TCP(dport=client_port, sport=server_port, seq=server_seq, ack=server_ack, flags=dpkt.tcp.TH_ACK)
            server_seq += len(data)
            new_tcp.data = data
            new_ip = deepcopy(ip_proto_server)
            new_ip.data = new_tcp
            packets.append(new_ip)

            # Create corresponding ACK
            client_ack = server_seq
            new_tcp = dpkt.tcp.TCP(sport=client_port, dport=server_port, seq=client_seq, ack=client_ack, flags=dpkt.tcp.TH_ACK)
            print("Sending server ack: ", client_ack)
            new_ip = deepcopy(ip_proto_client)
            new_ip.data = new_tcp
            packets.append(new_ip)
    # Close TCP connection
    fin = dpkt.tcp.TCP(sport=client_port, dport=server_port, seq=client_seq, ack=client_ack, flags=dpkt.tcp.TH_FIN)
    ip_fin = deepcopy(ip_proto_client)
    ip_fin.data = fin
    packets.append(ip_fin)

    fin_ack = dpkt.tcp.TCP(dport=client_port, sport=server_port, seq=server_seq, ack=server_ack, flags=dpkt.tcp.TH_FIN|dpkt.tcp.TH_ACK)
    ip_fin_ack = deepcopy(ip_proto_server)
    ip_fin_ack.data = fin_ack
    packets.append(ip_fin_ack)
    return packets

def main():
    with open('http_single.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packets = create_full_packets("1.2.3.4", "5.6.7.8", 80, 12345, pcap)
    with open('recreated.pcap', "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_RAW)
        for packet in packets:
            writer.writepkt(packet)

if __name__=="__main__":
    main()