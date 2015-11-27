import socket
import os
import struct
import ctypes
#from icmp_unpack import ICMP

# host to listen
HOST='192.168.1.36'

def sniffing(host,win,socket_prot):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
    sniffer.bind((host, 0))
    # include the IP headers in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if win == 1:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while 1:
        #print 'abc'
        raw_buffer = sniffer.recvfrom(65536)[0]
        ipheader = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s',ipheader)
        # read in a single packet
        # print sniffer.recvfrom(65565)

        #ipheader print
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        #udp hdr
        udphdr=raw_buffer[20:28]
        udph = struct.unpack("HHHH",udphdr)
        sport=socket.ntohs(udph[0])
        dport=socket.ntohs(udph[1])

        if s_addr == "192.168.1.36" or d_addr == "192.168.1.36":
            print 'IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
            ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:'\
             + str(s_addr) + ', Destination:' + str(d_addr) ,

            print '  Sport -> :' +  str(sport) +"   Dport -> " +str(dport)

def main(HOST):
    if os.name == 'nt':
        print "nt"
        sniffing(HOST, 1, socket.IPPROTO_IP)
    else:
        print("ab")
        sniffing(HOST, 1, socket.IPPROTO_UDP)

if __name__ == '__main__':
    main(HOST)