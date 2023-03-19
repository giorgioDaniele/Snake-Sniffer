import struct
from packetprint import printARP
from packetprint import printICMP
from packetprint import printTCP
from packetprint import printUDP

ARP  = '0x806'
IPV4 = '0x800'
UDP  = '0x11'
TCP  = '0x6'
ICMP = '0x1'


ETHERNET_PATTERN  = '!6s6sH'
IPV4_PATTERN      = '!8xBB2x4s4s'
TCP_PATTERN       = '!HHLLH'
ICMP_PATTERN      = '!BBHHH'
UDP_PATTERN       = '!HHHH'
ARP_PATTERN       = '!HHBBH6s4s6s4s'


def macAddress(bytes): return ':'.join(map(lambda value: '{:x}'.format(value) , bytes))
def ipAddress(bytes):  return '.'.join(map(lambda value: '{:d}'.format(value) , bytes))


def packetParser(nPacket, packet, arp = False, icmp = False, tcp = False, udp = False, counters = [0,0,0,0]):

    dstMAC, srcMAC, ethertype = struct.unpack(ETHERNET_PATTERN, packet[0:14])
    dstMAC = macAddress(dstMAC); srcMAC = macAddress(srcMAC); ethertype = hex(ethertype)

    result = 'Packet no° {}\n'.format(nPacket)

    if (ethertype == ARP and arp == True):
        #BLUE
        counters[0] += 1
        packet = packet[14:]
        hType, protoType, \
            hwAddrLen, protoAddrLen, opCode, \
                srcHwAddr, srcProtoAddr, tgtHwAddr, tgtProtoAddr = struct.unpack(ARP_PATTERN, packet[:28])
        result = printARP(nPacket, dstMAC, srcMAC, hType, protoType, hwAddrLen, protoAddrLen, opCode, macAddress(srcHwAddr), ipAddress(srcProtoAddr), macAddress(tgtHwAddr), ipAddress(tgtProtoAddr))
    if ethertype == IPV4:
        if(icmp == True or tcp == True or udp == True):
            packet = packet[14:]
            versionAndIHL = packet[0]
            version = versionAndIHL >> 4
            headerLength = (versionAndIHL & 15) * 4
            ttl, proto, srcIP, dstIP = struct.unpack(IPV4_PATTERN, packet[:20])
            dstIP = ipAddress(dstIP)
            srcIP = ipAddress(srcIP) 
            proto = hex(proto) 
            if (proto == TCP and tcp == True):
                #RED
                counters[1] += 1
                packet = packet[headerLength:]
                sport, dport, seq, ack, offsetReversedFlags = struct.unpack(TCP_PATTERN, packet[:14])
                offset   = (offsetReversedFlags >> 12)   *   4
                flagUrg  = (offsetReversedFlags &  32)   >>  5
                flagAck  = (offsetReversedFlags &  16)   >>  4
                flagPsh  = (offsetReversedFlags &   8)   >>  3
                flagRst  = (offsetReversedFlags &   4)   >>  2
                flagSyn  = (offsetReversedFlags &   2)   >>  1
                flagFin  = offsetReversedFlags  &   1
                result = printTCP(nPacket, dstMAC, srcMAC,version, headerLength, ttl, srcIP, dstIP, sport, dport, seq, ack, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, packet[offset:])
            if (proto == UDP and udp == True):
                #BLUE
                counters[2] += 1
                packet = packet[headerLength:]
                sport, dport, length, checksum = struct.unpack(UDP_PATTERN, packet[:8])
                result = printUDP(nPacket, dstMAC, srcMAC, version, headerLength, ttl, srcIP, dstIP, sport, dport, length, checksum)
            if (proto == ICMP and icmp == True):
                #YELLOW
                counters[3] += 1
                packet = packet[headerLength:]
                typeMsg, code, checksum, identifier, seqNumber = struct.unpack(ICMP_PATTERN,packet[:8])
                result = printICMP(nPacket, dstMAC, srcMAC, version, headerLength, ttl, srcIP, dstIP, typeMsg, code, checksum, identifier, seqNumber) 
    return result


    


