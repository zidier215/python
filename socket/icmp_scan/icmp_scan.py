import socket
import os
import struct
import ctypes
from icmp_unpack import ICMP
# host to listen
HOST='192.168.1.36'

def main(host):
    socketprotocal = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socketprotocal)
    sniffer.bind((host, 0))
    # include the IP headers in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    #sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print 'start captureing...'
    while 1:  # read in a single packet
        #print 'abc'
        raw_buffer = sniffer.recvfrom(65536)[0]
        ipheader = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s',ipheader)

        #ipheader print
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
        ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:'\
         + str(s_addr) + ', Destination:' + str(d_addr)

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        print "ICMP -> Type:%d, Code:%d" %(icmp_header.type, icmp_header.code) + '\n'
    print 'exit captureing...'


if __name__ == '__main__':
    main(HOST)