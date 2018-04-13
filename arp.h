//
//  arp.h
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef arp_h
#define arp_h

#define EPT_ARP 0x0806              // type: ARP

class Ether_header {
private:
    unsigned char ether_dhost[6];   // destination mac address
    unsigned char ether_shost[6];   // source mac address
    unsigned short ether_type;      // protocol type
public:
};

class Arp_header {
private:
    unsigned short arp_hrd;     // format of hardware address
    unsigned short arp_pro;     // format of protocol address
    unsigned char arp_hln;      // length of hardware address
    unsigned char arp_pln;      // length of protocol address
    unsigned short arp_op;      // ARP/RARP operation
    
    unsigned char arp_srch[6];  // source hardware address
    unsigned long arp_srcp;     // source protocol address
    unsigned char arp_dsth[6];  // destination hardware address
    unsigned long arp_dstp;     // destination protocol address
    
public:
};

class ArpPacket {
private:
    Ether_header ehhdr;
    Arp_header arphdr;
public:
};

#endif /* arp_h */
