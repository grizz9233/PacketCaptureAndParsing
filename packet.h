//
//  packet.h
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef packet_h
#define packet_h

#include <stdlib.h>
#include "packet.h"
#include <pcap/pcap.h>

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);

class Packet {
private:
    pcap_if_t* alldevs, *dev;
    pcap_t* adhandle;
public:
    void findalldevs();
    void choosedev();
    void capturePacket();
    void filter();
    /*
     pcap_t *adhandle = pcap_open_live(d->name, //适配器名字
     65535, //捕获包最大字节数 8
     1, //混杂模式
     1000, //读取超时时间
     errbuf );//错误信息保存
     pcap_close ( pcap_t *p);
     pcap_loop( adhanlde, 0, packet_handler, NULL);

     */
    
};

#endif /* packet_h */
