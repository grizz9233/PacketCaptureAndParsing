//
//  packet.h
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef packet_hpp
#define packet_hpp

#include "header.hpp"
#include <pcap/pcap.h>

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);

class Packet {
private:
    pcap_if_t* alldevs, *dev;
    pcap_t* adhandle;
public:
    void findalldevs();
    void choosedev();
    void capturePacket(int num, char filter[]);
    void filter(char filter[]);
    void send_single();
};

#endif /* packet_h */
