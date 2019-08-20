#ifndef ARP_SPOOFING_H
#define ARP_SPOOFING_H
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <pthread.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define ETHER_ADDR_LEN 6
#define ARP_TYPE 0x0608
#define ETH_HW 0x0100
#define IPv4 0x0008
#define ARP_REQ 0x0100
#define ARP_REP 0x0200


struct	ether_header {
    u_int8_t    ether_dhost[ETHER_ADDR_LEN];
    u_int8_t    ether_shost[ETHER_ADDR_LEN];
    u_int16_t   ether_type;
};

struct arp_header {
    u_short arp_htype; /*hardware type*/
    u_short arp_p; /*protocol*/
    u_char arp_hsize; /*hardware size*/
    u_char arp_psize; /*protocol size*/
    u_short arp_opcode; /*opcode*/
    u_char arp_smhost[6]; /*sender mac address*/
    u_char arp_sip[4];
    u_char arp_dmhost[6]; /*target mac address*/
    u_char arp_dip[4];

};

struct session{
    char* sender;
    char* target;
};




char* dev;
unsigned char macArr[10];
unsigned char *My_MAC = macArr;
char myIP[40] = "10.211.55.4";

#endif // ARP_SPOOFING_H
