//
//  main.cpp
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#include "packet.hpp"

int main() {
    printf("All interfaces: \n");
    Packet packet;
    packet.findalldevs();
    packet.choosedev();
    bool loop = true;
    while (loop) {
        setbuf(stdin, NULL);
        printf("Choose to send a packet(1) or capture a packet(2) (any other characters will stop this program): ");
        int choice;
        scanf("%d", &choice);
        if (choice == 2) {
            char ch;
            while((ch=getchar())!='\n'&&ch!=EOF);
            printf("Please input filter string: ");
            char filter[30];
            cin.getline(filter, 30);
            printf("Please input the number of packet you would like to capture: ");
            int num;
            scanf("%d", &num);
            printf("\n");
            packet.filter(filter);
            packet.capturePacket(num, filter);
        } else if (choice == 1) {
            packet.send_single();
        } else {
            loop = false;
        }
    }
    return 0;
}

