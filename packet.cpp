//
//  packet.cpp
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#include "packet.hpp"

void Packet::findalldevs() {
    pcap_if_t *_alldevs, *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&_alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(1);
    }
    for (d = _alldevs; d; d = d->next){
        printf("\t%d. %s", ++i, d->name);
        if (d->description){
            printf(" (%s)\n", d->description);
        }
        else {
            printf(" (No description available)\n");
        }
    }
    if (i==0) {
        printf("\nNo interfaces found! \n");
        return ;
    }
    // pcap_freealldevs(alldevs);
    alldevs = _alldevs;
}

void Packet::choosedev() {
    printf("Please select a dev by inputting the number of the dev: ");
    int num;
    pcap_if_t *d = alldevs;
    scanf("%d", &num);
    for (int j = 1; j < num; j++) {
        d = d->next;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *_adhandle = pcap_open_live(d->name,  // device name
                                       65535,    // snaplen
                                       1,        // promisc
                                       1000,     // to_ms
                                       errbuf);  // *ebuf
    if (_adhandle == NULL) {
        fprintf(stderr,"Error in pcap_open_live: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(1);
    }
    dev = d;
    adhandle = _adhandle;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    local_tv_sec = pkt_header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    printf("%s.%.6d len:%d ", timestr, pkt_header->ts.tv_usec, pkt_header->len);
    // parse
    Ether_header ethhdr;
    ethhdr = *(Ether_header*)(pkt_data);
    switch (ntohs(ethhdr.ether_type)) {
        case ETH_ARP:
            Arp_header arphdr;
            arphdr = *(Arp_header*)(pkt_data + 14);
            arphdr.arp_parse();
            break;
        case ETH_IP:
            Ipv4_header ipv4hdr;
            ipv4hdr = *(Ipv4_header*)(pkt_data + 14);
            ipv4hdr.ipv4_parse(pkt_data);
            break;
        default:
            break;
    }
    printf("\n");
}

void Packet::capturePacket(int num, char filter[]) {
    pcap_loop(adhandle, num, packet_handler, NULL);
}

void Packet::filter(char filter[]) {
    u_int netmask, netip;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* packet_filter = filter;
    struct bpf_program fcode;
    if (dev->addresses != NULL) {
        if (pcap_lookupnet(dev->name, &netip, &netmask, errbuf) == -1) {
            fprintf(stderr,"Error in pcap_lookupnet: %s\n", errbuf);
            pcap_freealldevs(alldevs);
            exit(1);
        }
    }
    else {
        netmask=0xffffff;
    }
    if (pcap_compile(adhandle, &fcode, packet_filter, 0, netmask) < 0) {
        fprintf(stderr,"\nUnable to compile the filter. Check the syntax.\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }
    if (pcap_setfilter(adhandle, &fcode)<0) {
        fprintf(stderr,"\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }
}

void Packet::send_single() {
    bool loop = true;
    char length[4];
    u_char* packet;
    while (loop) {
        printf("Please input the packet length of the data you would like to send or type \"*\" to send the default packet: ");
        scanf("%s", length);
        if (length[0] == '*') {
            packet = new u_char[100];
            for (int i = 0; i < 100; i++) {
                if (i < 6) {
                    packet[i] = 1;
                } else if (i < 12) {
                    packet[i] = 2;
                } else {
                    packet[i] = i % 256;
                }
            }
            if (pcap_sendpacket(adhandle, packet, 100) != 0) {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
            }
        } else {
            int len = atoi(length);
            if (len > MAXLENGTH) {
                printf("Wrong length.\n");
            } else {
                int flag = 0;
                packet = new u_char[len];
                u_char tmp = 0;
                char ch;
                while((ch=getchar())!='\n'&&ch!=EOF);
                printf("Please input data: ");
                int i;
                for (i = 0; i < len*2; i++) {
                    char w;
                    scanf("%c", &w);
                    if (('0' <= w && w <= '9') || ('a' <= w && w <= 'f') || w == '\n' || w == ' ') {
                        if (i%2 == 0) {
                            if ('0' <= w && w <= '9') {
                                tmp = w - '0';
                            } else if ('a' <= w && w <= 'f') {
                                tmp = 10 + w - 'a';
                            } else {
                                i--;
                            }
                        } else {
                            packet[i/2] = tmp * 16 + w - '0';
                        }
                    } else {
                        printf("Wrong data.\n");
                        flag = 1;
                        break;
                    }
                }
                if (flag == 1) {
                    break;
                }
                if (pcap_sendpacket(adhandle, packet, len) != 0) {
                    fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
                }
            }
        }
        char ch;
        while((ch=getchar())!='\n'&&ch!=EOF);
        printf("Sending one packet more? (please input 1/0) ");
        while (1) {
            int lp;
            scanf("%d", &lp);
            if (lp == 1) {
                break;
            } else if (lp == 0) {
                loop = false;
                break;
            } else {
                printf("Try again.\n");
            }
        }
    }
}
