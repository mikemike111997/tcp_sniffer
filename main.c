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
#include <pthread.h>
#include "tcp_connection_info.h"


enum STATUS_CODES
{
    SUCCESS = 0,
    PCAP_INITIALIZE_ERROR = 1
};

static node_t* listHead;

pthread_mutex_t lock;

static void packetHandler(u_char* userData __attribute__((unused)),
                          const struct pcap_pkthdr* pkthdr __attribute__((unused)),
                          const u_char* packet)
{
    const struct ether_header* ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    if (ipHeader->ip_p != IPPROTO_TCP)
    {
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
     
        pthread_mutex_lock(&lock);
        updateConnectionInfoList(&listHead, &info);
        pthread_mutex_unlock(&lock);
    }
}

static void* analyzeTrafficThreadFunct(void* devName)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};    // pcap error buffer
    struct bpf_program fp;                  // The compiled filter expression 
    static const char filter_exp[] = "tcp"; // The filter expression
    bpf_u_int32 mask = 0;                   // The netmask of our sniffing device
    bpf_u_int32 net = 0;                    // The IP of our sniffing device

    const char* dev = (const char*)devName;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "pcap_lookupnet failed for device %s\n", dev);
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
    else
    {
        struct in_addr ip_addr = {.s_addr = net};
        struct in_addr ip_mask_addr = {.s_addr = mask};
        printf("Device: %s ", dev);
        printf("Network: %s ", inet_ntoa(ip_addr));
        printf("Mask = %s\n", inet_ntoa(ip_mask_addr));
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return NULL;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    pcap_loop(handle, -1, packetHandler, NULL);

    // clean up resources
    pcap_close(handle);
    pcap_freecode(&fp);

    return NULL;
}

static uint8_t isCapturebleDevie(pcap_if_t* it)
{
    pcap_addr_t *dev_addr; //interface address that used by pcap_findalldevs()

    /* check if the device captureble*/
    for (dev_addr = it->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
        if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask) {
           return 1;
        }
    }
    return 0;
}

static size_t coundDevicesAvaiilable(pcap_if_t* it)
{
    size_t res = 0;
    while (it)
    {
        if (isCapturebleDevie(it))
            ++res;
        it = it->next;
    } 

    return res;
}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; // pcap error buffer
    pcap_if_t *it = NULL;

    if(pcap_findalldevs(&it, errbuf) == 0)
    {
        pcap_if_t* current = it;
        const size_t availableDevicesCount = coundDevicesAvaiilable(it);

        printf("Number of available devices for TPC traffic sniffing: %lu\n", availableDevicesCount);

        pthread_t threads[availableDevicesCount];
        memset(&threads, 0, sizeof(threads));

        // spawn worker threads
        for (size_t i = 0; i < availableDevicesCount; ++i)
        {
            if (isCapturebleDevie(it))
            {
                if (pthread_create(&threads[i], NULL, &analyzeTrafficThreadFunct, (void*)current->name))
                    fprintf(stderr, "Thead creation failed for the dev %s", current->name);
            }

            current = current->next;
        }

        // join threads
        for (size_t i = 0; i < availableDevicesCount; ++i)
        {
            if (pthread_join(threads[i], NULL))
                fprintf(stderr, "Thead join failed!");
        }

        // clear resources
        pcap_freealldevs(it);
    }
    else
    {
        fprintf(stderr, "pcap_findalldevs failed.\n");
        fprintf(stderr, "%s\n", errbuf);
        return PCAP_INITIALIZE_ERROR;
    }

    deleteList(&listHead);

    return SUCCESS;
}