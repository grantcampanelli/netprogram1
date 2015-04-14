/*
 *  Created by Grant Campanelli on 4/8/15.
 *  Trace.c
 *
 *
 */

#include <pcap/pcap.h>
#include "trace.h"
#include "checksum.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void printMacAddr(unsigned char * addr) {
    int i = 0;

    for(i = 0; i < ARP_MAC_ADDR_LEN; i++) {
        if(i)
            printf(":");
        printf("%x", addr[i]);
    }
}

void printIPAddr(unsigned char * addr) {
    int i = 0;

    for(i = 0; i < ARP_IP_ADDR_LEN; i++) {
        if(i)
            printf(".");
        printf("%u", addr[i]);
    }
};

void arpRead(const unsigned char *packet) {
    struct sniff_arp *arp = malloc(sizeof(struct sniff_arp));
    memcpy(arp, packet + ETHER_SIZE, sizeof(struct sniff_arp));
    printf("\tARP header\n");
    if(endian(arp->arp_opcode) & 2)
        printf("\t\tOpcode: Reply\n");
    else
        printf("\t\tOpcode: Request\n");

    printf("\t\tSender MAC: ");
    printMacAddr(arp->arp_send_mac_addr);
    printf("\n\t\tSender IP: ");
    printIPAddr(arp->arp_send_ip_addr);
    printf("\n\t\tTarget MAC: ");
    printMacAddr(arp->arp_targ_mac_addr);
    printf("\n\t\tTarget IP: ");
    printIPAddr(arp->arp_targ_ip_addr);
    printf("\n\n");
}

/*
 * cap_len = header.caplen
 * ts = header.ts
 */

void ethernetRead(const unsigned char *packet, struct pcap_pkthdr header) {
    struct sniff_ethernet *eth = malloc(sizeof(struct sniff_ethernet));
    memcpy(eth, packet, sizeof(struct sniff_ethernet));
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: ");
    printMacAddr(eth->eth_dest);
    printf("\n\t\tSource MAC: ");
    printMacAddr(eth->eth_src);

    printf("\n\t\tType: ");

    // fix this
    if(eth->eth_type == ARP_FLAG) {
        printf("ARP\n\n");
        arpRead(packet);
    }
    else if(eth->eth_type == IP_FLAG) {
        printf("IP\n\n");
        ipRead(packet, header);
    }
    else {
        printf("Unkown\n\n");
    }

}
/*
 * IP
 *      TOS: 4
        Time to live:
        Protocol:
        Header checksum:
       Source IP:
       Destination IP:
       */

void ipRead(const unsigned char *packet, struct pcap_pkthdr header) {
    struct sniff_ip *ip = malloc(sizeof(struct sniff_ip));
    int flag = 0;
    memcpy(ip, packet + ETHER_SIZE, sizeof(struct sniff_ip));
    int checksum = 1;
    printf("\tIP Header\n");
    printf("\t\tTOS: 0x%x\n", ip->ip_tos);
    printf("\t\tTTL: %u\n", ip->ip_ttl);
    printf("\t\tProtocol: ");

    //printf("%02x\n", ip->ip_protocol);
    switch(ip->ip_protocol) {
        case IP_ICMP:
            printf("ICMP\n");
            flag = 1;
            break;
        case IP_TCP:
            printf("TCP\n");
            flag = 2;
            break;
        case IP_UDP:
            printf("UDP\n");
            flag = 3;
            break;
        default:
            printf("Unknown\n");
            flag = -1;
            break;
    }

    checksum = in_cksum((unsigned short *) packet + ETHER_SIZE, header.len);
    if(!checksum)
        printf("\t\tChecksum: Correct (0x%04x)\n", endian(ip->ip_sum));
    else
        printf("\t\tChecksum: Incorrect (0x%04x)\n", endian(ip->ip_sum));

    printf("\t\tSender IP: ");
    printIPAddr(ip->ip_source);
    printf("\n\t\tDest IP: ");
    printIPAddr(ip->ip_dest);
    printf("\n");

    ipDistribute(packet, flag);
}

void ipDistribute(const unsigned char *packet, int flag){

    switch(flag) {
        case 1:
            //printf("Distribute ICMP\n");
            icmpRead(packet);
            break;
        case 2:
            //printf("Distribute TCP\n");
            break;
        case 3:
            //printf("Distribute UDP\n");
            break;
        default:
            break;
    }
}

void icmpRead(const unsigned char *packet) {
    unsigned char * addr = ((unsigned char *)packet + ETHER_SIZE + sizeof(struct sniff_ip));
    unsigned char type= (unsigned char) *addr;
    printf("\n\tICMP Header\n");

    switch(type) {
        case IP_ICMP_REQUEST:
            printf("\t\tType: Request\n");
            break;
        case IP_ICMP_REPLY:
            printf("\t\tType: Reply\n");
            break;
        default:
            printf("\t\tType: Unknown\n");
            break;
    }
//    switch(type) {
//        case IP_ICMP_REQUEST:
//            printf("\t\tType: Request %x\n", type);
//            break;
//        case IP_ICMP_REPLY:
//            printf("\t\tType: Reply %x\n", type);
//            break;
//        default:
//            printf("\t\tType: Unknown %x\n", type);
//            break;
//    }

/*
    if(!(type & -1))
        printf("\t\tType: Request %x\n", type);
    else if(type == 8)
        printf("\t\tType: Reply %x\n", type);
    else
        printf("\t\tType: Unknown %x\n", type);
*/

}

void tcpRead(void) {
    printf("\tTCP:\n");
}

void udpRead(void) {
    printf("\tUDP:\n");
}

/*void packetDistribute(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    ethernetRead(packet);
    ipRead();
    icmpRead();
    tcpRead();
    udpRead();
}*/

void packetDistribute(const unsigned char *packet, struct pcap_pkthdr header) {
    ethernetRead(packet, header);
/*
    ipRead();
    icmpRead();
    tcpRead();
    udpRead();
    */
}

int main(int argc, char **argv) {
    pcap_t *pcapFile;
    int counter = 1;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;


    if((pcapFile = pcap_open_offline(argv[1], errbuf)) == NULL) {
        printf("pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    // change if to while for multiple packets
    while((packet = pcap_next(pcapFile, &header)) != NULL) {
        printf("\nPacket number: %i  Packet Len: %i\n\n", counter++, header.len);
        packetDistribute(packet, header);
    };
    /*if((packet = pcap_next(pcapFile, &header)) != NULL) {
        printf("Packet number: %i  Packet Len: %i\n\n", counter++, header.len);
        NewDistribute(packet, header);
    };*/

/*

    if (pcap_loop(pcapFile, 0, packetDistribute, NULL) < 0) {
        printf("pcap_loop() failed: %s\n", pcap_geterr(pcapFile));
        return 1;
    }
*/



    pcap_close(pcapFile);
    return 0;
}

