//
//  ipv4.h
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef ipv4_h
#define ipv4_h

class ipv4_header {
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
public:
    <#member functions#>
};

#endif /* ipv4_h */
