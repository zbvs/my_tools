
import socket, sys
import zlib
import struct
import time


def ip_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = (s + w ) & 0xffffffff
        s = (s&0xffff) + (s >> 16) # end around carry https://tools.ietf.org/html/rfc1071#page-2
    s = s >> 8 | (s << 8 & 0xff00)
    return ~s & 0xffff


def tcp_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
    	w = msg[i] + (msg[i+1] << 8 )
    	s = s + w
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    s = ~s & 0xffff
    return s


# the main function
def get_ip_packet(source_ip,dest_ip, proto="ICMP"):
    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
    # now start constructing the packet
    packet = ""

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = 0x8dbd	#Id of this packet
    ip_frag_off = 0x4000
    ip_ttl = 64
    
    ip_check = 0	
    ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl


    if proto == "ICMP":
        payload = get_icmp_packet()
        ip_proto =socket.IPPROTO_ICMP
    else:
        payload = get_tcp_packet(source_ip, dest_ip)
        ip_proto = socket.IPPROTO_TCP
    

    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_tot_len = len(ip_header + payload) 
    if ip_tot_len > 1500:
        raise Exception("if ip_tot_len > 1500:")
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_check = ip_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    packet = ip_header + payload
    return packet

def get_tcp_packet(source_ip, dest_ip):
    # tcp header fields
    tcp_source = 1234	# source port
    tcp_dest = 4444	# destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)	#	maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    user_data = 'Hello, how are you'

    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data.encode();

    tcp_check = tcp_checksum(psh)

    tcp_header = struct.pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + struct.pack('H' , tcp_check) + struct.pack('!H' , tcp_urg_ptr)
    return tcp_header + user_data.encode()


def get_icmp_packet():
    default_timer = time.time
    ICMP_ECHO_REQUEST = 8
    my_checksum = 0x0
    ID = 0x1500
    SEQ = 0x0100
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, SEQ)
    bytesInDouble = struct.calcsize("d")
    

    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", default_timer()) + data.encode()
    data = bytes.fromhex("17 ec 01 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 37 37 37 37 37 37 37 37".replace(" ",""))
    


    my_checksum = ip_checksum(header + data)
    print("header ", header + data)
    print("icmp my_checksum:%x" % my_checksum)

    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, SEQ
    )
    
    packet = header + data
    return packet


def main():
    ETH_P_ALL = 3
    br_ce9096d26fb7 = "02:42:ae:9b:2b:43"
    docker0 = "02:42:75:40:8c:1f"
    ens33 = "00:0c:29:2d:1c:e3"
    kube_node = "02:42:c0:a8:31:02"
    uni = "00:00:00:00:00:00"

    test_server = "04:d9:f5:81:d1:57"
    
    ens33 = {"name":"ens33","mac":"00:0c:29:2d:1c:e3"}
    br_ce9096d26fb7 = {"name":"br-ce9096d26fb7","mac":"02:42:ae:9b:2b:43"}


    inf = ens33
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((inf["name"], 0))

    


    src_mac = ens33["mac"]
    dst_mac = kube_node

    
    src_addr = bytes.fromhex(src_mac.replace(":",""))
    dst_addr = bytes.fromhex(dst_mac.replace(":",""))


    kube_node_ip = "192.168.49.2"
    br_ip = "192.168.49.1"
    test_server = "192.168.219.25"
    my_ip = "192.168.219.23"

    source_ip = my_ip   
    dest_ip = br_ip
    ethertype = struct.pack("H",0x8)

    payload = get_ip_packet(source_ip, dest_ip)
    
    #crc = zlib.crc32(payload)
    #checksum = struct.pack('>I',crc)
    #s.send(dst_addr+src_addr+ethertype+payload+checksum)

    s.send(dst_addr+src_addr+ethertype+payload)
    
    print("rec:" ,s.recv(1000) )



main()





