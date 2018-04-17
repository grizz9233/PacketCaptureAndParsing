//
//  header.hpp
//  pcap
//
//  Created by Tangrizzly on 2018/4/17.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef header_hpp
#define header_hpp

#include <iostream>
#include <time.h>
#include <math.h>
#include <string>
using namespace std;

#define ETH_ARP         0x0806
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define ETH_IP          0x0800
#define IP_ICMP         1
#define ICMP_ECHO_REP   0           // echo reply
#define ICMP_DIST_UNRE  3           // destination unreachable
#define ICMP_REDIR      5           // redirect
#define ICMP_ECHO_REQ   8           // echo request
#define ICMP_TIME_EX    11          // time exceed
#define ICMP_TIME_REQ   13          // timestamp request
#define ICMP_TIME_REP   14          // timestamp reply
#define ICMP_ADDR_M_REQ 17          // address mask request
#define ICMP_ADDR_M_REP 18          // address mask reply
#define UNR_NEWWORK     0           // network unreachable
#define UNR_HOST        1           // host unreachable
#define UNR_PROTOCOL    2           // protocol unreachable
#define UNR_PORT        3           // port unreachable
#define UNR_DES_N_U     6           // destination network unknown
#define UNR_DES_H_U     7           // destination host unknown
#define UNR_SRC_H_I     8           // source host isolated
#define MAXLENGTH       1518

class Ether_header {
public:
    unsigned char ether_dhost[6];   // destination mac address(6)
    unsigned char ether_shost[6];   // source mac address(6)
    unsigned short ether_type;      // protocol type(2)
};

class Arp_header {
public:
    unsigned short arp_hrd;     // format of hardware address(2)
    unsigned short arp_pro;     // format of protocol address(2)
    unsigned char arp_hln;      // length of hardware address(1)
    unsigned char arp_pln;      // length of protocol address(1)
    unsigned short arp_op;      // ARP/RARP operation(2)
    
    unsigned char arp_srch[6];  // source hardware address(6)
    unsigned char arp_srcp[4];  // source protocol address(4)
    unsigned char arp_dsth[6];  // destination hardware address(6)
    unsigned char arp_dstp[4];  // destination protocol address(4)
    
    void arp_parse();
};

class Ipv4_header {
public:
    unsigned char ver_ihl;          // version(4 bits) + head length(4 bits)
    unsigned char tos;              // service type
    unsigned short tlen;            // total length
    unsigned short identification;  // identification
    unsigned short flags_fo;        // flag(3 bits) + fragment offset(13 bits)
    unsigned char ttl;              // time to live
    unsigned char proto;            // protocol
    unsigned short crc;             // checksum
    u_char ip_src[4];               // source IP address
    u_char ip_dst[4];               // destination IP address
    
    void ipv4_parse(const u_char* pkt_data);
};

class Icmp_header {
public:
    unsigned char type;
    unsigned char code;
    unsigned short crc;
    unsigned short identification;
    unsigned short sequence;
    
    void icmp_parse();
};
#endif /* header_hpp */
