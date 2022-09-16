/**
 * @file main.c
 * @author Mykhailo Lohvynenko (mikemike111997@gmail.com)
 * @brief C application which analyzes traffic on a given network interface and
 *        reports to stdout all successful and failed connections.
 *        AC1: If a failed connection is repeated with the same source ip, destination ip and
 *             destination port (source ports can differ), add a count to the report
 * @version 0.1
 * @date 2022-09-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include "tcp_connection_info.h"


enum STATUS_CODES
{
    SUCCESS = 0,
    INVALID_ARGV = 1,
    PCAP_INITIALIZE_ERROR = 2
};

static node_t* listHead;

static void packetHandler(u_char* userData __attribute__((unused)),
                          const struct pcap_pkthdr* pkthdr __attribute__((unused)),
                          const u_char* packet)
{
    const struct ether_header* ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP)
    {
        fprintf(stderr, "Not an IP package, skipping it!\n");
        return;
    }

    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    if (ipHeader->ip_p != IPPROTO_TCP)
    {
        fprintf(stderr, "Not a TCP package, skipping it!\n");
        return;
    }

    const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    // No need to check other packages
    if (tcpHeader->th_flags & (TH_SYN | TH_ACK))
    {
        tcp_connection_info_t info = {
            .clientIP = ipHeader->ip_src,
            .clientPort = tcpHeader->source,
            .serverIP = ipHeader->ip_dst,
            .serverPort = tcpHeader->dest,
            .lastFlag = tcpHeader->th_flags,
            .retryCount = 0,
            .handshakeSucceeded = 0
        };
     
        updateConnectionInfoList(&listHead, &info);
    }
}

int main(int argC, char* argV[])
{
    if (argC != 2)
    {
        fprintf(stderr, "Error: expected device name as an input param");
        return INVALID_ARGV;
    }
 
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; // pcap error buffer
    struct bpf_program fp;               // The compiled filter expression 
    const char filter_exp[] = "tcp ";    // The filter expression
    bpf_u_int32 mask = 0;                // The netmask of our sniffing device
    bpf_u_int32 net = 0;                 // The IP of our sniffing device

    char* dev = argV[1];
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "pcap_lookupnet failed for device %s\n", dev);
        fprintf(stderr, "%s\n", errbuf);
        return PCAP_INITIALIZE_ERROR;
    }
    else
    {
        struct in_addr ip_addr = {.s_addr = net};
        struct in_addr ip_mask_addr = {.s_addr = mask};
        printf("Device: %s\n", dev);
        printf("Network: %s\n", inet_ntoa(ip_addr));
        printf("Mask = %s\n", inet_ntoa(ip_mask_addr));
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return PCAP_INITIALIZE_ERROR;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return PCAP_INITIALIZE_ERROR;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return PCAP_INITIALIZE_ERROR;
    }

    pcap_loop(handle, -1, packetHandler, NULL);

    // clean up resources
    pcap_close(handle);
    pcap_freecode(&fp);
    deleteList(&listHead);

    return SUCCESS;
}