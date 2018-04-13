//
//  packet.cpp
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#include "packet.h"

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
        printf("%d. %s", ++i, d->name);
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
    printf("Please select a dev by inputting the number of the dev:");
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

void Packet::capturePacket() {
    pcap_loop(adhandle, 0, packet_handler, NULL);
}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    // todo
    return ;
}

void Packet::filter() {
    u_int netmask, netip;
    char errbuf[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "arp";
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
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
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
