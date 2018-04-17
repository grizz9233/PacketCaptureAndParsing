//
//  header.cpp
//  pcap
//
//  Created by Tangrizzly on 2018/4/17.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#include "header.hpp"

void Arp_header::arp_parse() {
    printf("\n------------ ARP -------------\n");
    printf("Hardware type: %s\n", (ntohs(arp_hrd) == 1)?"Ethernet":"Unknown");
    printf("Protocol type: %s\n", (ntohs(arp_pro) == 0x0800)?"IPv4":"Unknown");
    printf("Operation : %s\n", (ntohs(arp_op) == ARP_REQUEST)?"ARP_REQUEST":"ARP_REPLY");
    printf("Soucre MAC :%02x:%02x:%02X:%02x:%02x:%02x\n",
           arp_srch[0], arp_srch[1],
           arp_srch[2], arp_srch[3],
           arp_srch[4], arp_srch[5]);
    printf("Soucre IP :%d.%d.%d.%d\n",
           arp_srcp[0], arp_srcp[1],
           arp_srcp[2], arp_srcp[3]);
    printf("Destination MAC :%02x:%02x:%02X:%02x:%02x:%02x\n",
           arp_dsth[0], arp_dsth[1],
           arp_dsth[2], arp_dsth[3],
           arp_dsth[4], arp_dsth[5]);
    printf("Destination IP :%d.%d.%d.%d\n",
           arp_dstp[0], arp_dstp[1],
           arp_dstp[2], arp_dstp[3]);
}

void Ipv4_header::ipv4_parse(const u_char* pkt_data) {
    printf("\n------------ IP -------------\n");
    printf("Version: %u, Head length: %u\n",
           ver_ihl>>4, ver_ihl&0x0f);
    printf("Total length: %u\n", tlen);
    printf("Identification: %u\n", identification);
    printf("Flag: %u, Fragment offset: %u\n", flags_fo>>13, flags_fo&0x1F);
    printf("Survival time: %u\n", ttl);
    printf("Protocol: %s\n", ntohs(proto)==IP_ICMP?"ICMP":"Unknown");
    printf("Checksum: %u\n", crc);
    printf("Source ip address: %u.%u.%u.%u\n",
           ip_src[0], ip_src[1],
           ip_src[2], ip_src[3]);
    printf("Destination ip address: %u.%u.%u.%u\n",
           ip_dst[0], ip_dst[1],
           ip_dst[2], ip_dst[3]);
    if (proto == IP_ICMP) {
        Icmp_header icmphdr;
        icmphdr = *(Icmp_header*)(pkt_data + (ver_ihl&0x0f)*8);
        icmphdr.icmp_parse();
    }
}


void Icmp_header::icmp_parse() {
    printf("------------ ICMP -------------\n");
    string type;
    string code;
    switch (ntohs(this->type)) {
        case ICMP_ECHO_REP:
            type = "Echo reply";
            break;
        case ICMP_DIST_UNRE:
            type = "Destination unreachable";
            switch (ntohs(this->code)) {
                case UNR_NEWWORK:
                    code = "network unreachable";
                    break;
                case UNR_HOST:
                    code = "Host unreachable";
                    break;
                case UNR_PROTOCOL:
                    code = "Protocol unreachable";
                    break;
                case UNR_PORT:
                    code = "Port unreachable";
                    break;
                case UNR_DES_N_U:
                    code = "Destination network unknown";
                    break;
                case UNR_DES_H_U:
                    code = "Destination host unknown";
                    break;
                case UNR_SRC_H_I:
                    code = "Source host isolated";
                    break;
                default:
                    code = "Unknown";
                    break;
            }
            break;
        case ICMP_REDIR:
            type = "Redirect";
            code = "Unknown";
            break;
        case ICMP_ECHO_REQ:
            type = "Echo request";
            break;
        case ICMP_TIME_EX:
            type = "Time exceed";
            code = "Unknown";
            break;
        case ICMP_TIME_REQ:
            type = "Timestamp request";
            break;
        case ICMP_TIME_REP:
            type = "Timestamp reply";
            break;
        case ICMP_ADDR_M_REQ:
            type = "Address mask request";
            break;
        case ICMP_ADDR_M_REP:
            type = "Address mask reply";
            break;
        default:
            type = "Unknown";
            break;
    }
    printf("ICMP type: %s\n", type.c_str());
    if (!code.empty()) {
        printf("ICMP code: %s\n", code.c_str());
    }
    printf("Checksum: %u\n", crc);
    printf("Identification: %u\n", identification);
    printf("Squence number: %u\n", sequence);
}
