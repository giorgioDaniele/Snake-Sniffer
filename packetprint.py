ICMP_REQUEST = 8
ICMP_REPLY   = 0

ARP_REQUEST  = 1
ARP_REPLY    = 0

            # Ethernet level
def printARP(nPacket, dstMAC, srcMAC,
             # ARP level
             hType, protoType, hwAddrLen, protoAddrLen, opCode, srcHwAddr, srcProtoAddr, tgtHwAddr, tgtProtoAddr):
    return \
    '####################################################################################\n' + \
    'Packet no° {}\n'.format(nPacket) + \
    '   --|Ethernet Frame|:\n' + \
    '       |Dst MAC:   {}|\n'.format(dstMAC) + \
    '       |Src MAC:   {}|\n'.format(srcMAC) + \
    '       |Ethertype: ARP|\n' + \
    '       --|ARP Message|:\n' + \
    '           |Hardware  Type: {}|\n'.format(hType) + \
    '           |Protocol  Type: {}|\n'.format(protoType) + \
    '           |Hardware Address Length: {}|\n'.format(hwAddrLen) + \
    '           |Protocol Address Length: {}|\n'.format(protoAddrLen) + \
    '           |Operation Code: {}|\n'.format('ARP Request' if opCode == ARP_REQUEST else 'ARP Reply') + \
    '           |Src Hardware Address: {}|\n'.format(srcHwAddr) + \
    '           |Src Protocol Address: {}|\n'.format(srcProtoAddr) + \
    '           |Target Hardware Address: {}|\n'.format(tgtHwAddr) + \
    '           |Target Protocol Address: {}|\n'.format(tgtProtoAddr)

               # Ethernet level
def printICMP(nPacket, dstMAC, srcMAC, 
               # IPv4 level
               version, headerLength, ttl, srcIP, dstIP, 
               # ICMP level
               typeMsg, code, checksum, identifier, seqNumber):
    
    return  \
    '####################################################################################\n' + \
    'Packet no° {}\n'.format(nPacket) + \
    '   --|Ethernet Frame|:\n' + \
    '       |Dst MAC:   {}|\n'.format(dstMAC) + \
    '       |Src MAC:   {}|\n'.format(srcMAC) + \
    '       |Ethertype: IPv4|\n'+ \
    '       --|IP Datagram|:\n' + \
    '            |Version: {}|\n'.format(version) + \
    '            |IHL: {}|\n'.format(headerLength) + \
    '            |TTL: {}|\n'.format(ttl) + \
    '            |Protocol: ICMP|\n' + \
    '            |Src IP: {}|\n'.format(srcIP) + \
    '            |Dst IP: {}|\n'.format(dstIP) + \
    '               --|ICMP Message|\n' + \
    '                   |Type:       {}|\n'.format('ICMP Request' if typeMsg == ICMP_REQUEST else 'ICMP Reply') + \
    '                   |Code:       {}|\n'.format(code) + \
    '                   |Checksum:   {:x}|\n'.format(checksum) + \
    '                   |Identifier: {}|\n'.format(identifier) + \
    '                   |Seq Number: {}|\n'.format(seqNumber)
       
            # Ethernet level
def printTCP(nPacket, dstMAC, srcMAC, 
             # IPv4 level
            version, headerLength, ttl, srcIP, dstIP,
            # TCP level
            sport, dport, seq, ack, flagUrg, flagAck,flagPsh, flagRst, flagSyn, flagFin,
            # TCP data
            data): 
    return \
    '####################################################################################\n' + \
    'Packet no° {}\n'.format(nPacket) + \
    '   --|Ethernet Frame|:\n' + \
    '       |Dst MAC:   {}|\n'.format(dstMAC) + \
    '       |Src MAC:   {}|\n'.format(srcMAC) + \
    '       |Ethertype: IPv4|\n'+ \
    '       --|IP Datagram|:\n' + \
    '            |Version: {}|\n'.format(version) + \
    '            |IHL: {}|\n'.format(headerLength) + \
    '            |TTL: {}|\n'.format(ttl) + \
    '            |Protocol: TCP|\n' + \
    '            |Src IP: {}|\n'.format(srcIP) + \
    '            |Dst IP: {}|\n'.format(dstIP) + \
    '               --|TCP Segment:|\n' + \
    '                   |Src Port: {}|\n'.format(sport) + \
    '                   |Dst Port: {}|\n'.format(dport) + \
    '                       |Seq: {}|\n'.format(seq) + \
    '                       |Ack: {}|\n'.format(ack) + \
    '                       |Flags|:\n' + \
    '                           -URG: {}, -ACK: {}, -PSH:{}\n'.format(flagUrg, flagAck, flagPsh) + \
    '                           -RST: {}, -SYN: {}, -FIN:{}\n'.format(flagRst, flagSyn, flagFin) 

def printUDP(nPacket, dstMAC, srcMAC,
                                   version, headerLength, ttl, srcIP, dstIP,
                                   sport, dport, length, checksum):
    return  \
    '####################################################################################\n' + \
    'Packet no° {}\n'.format(nPacket) + \
    '   --|Ethernet Frame|:\n' + \
    '       |Dst MAC:   {}|\n'.format(dstMAC) + \
    '       |Src MAC:   {}|\n'.format(srcMAC) + \
    '       |Ethertype: IPv4|\n'+ \
    '       --|IP Datagram|:\n' + \
    '            |Version: {}|\n'.format(version) + \
    '            |IHL: {}|\n'.format(headerLength) + \
    '            |TTL: {}|\n'.format(ttl) + \
    '            |Protocol: UDP|\n' + \
    '            |Src IP: {}|\n'.format(srcIP) + \
    '            |Dst IP: {}|\n'.format(dstIP) + \
    '               --|UDP Segment|\n' + \
    '                   |Src Port: {}|\n'.format(sport) + \
    '                   |Dst Port: {}|\n'.format(dport) + \
    '                       |Length:     {}|\n'.format(length) + \
    '                       |Checksum: {:x}|\n'.format(checksum) 