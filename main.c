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


enum STATUS_CODES
{
    SUCCESS = 0,
    INVALID_ARGV = 1,
    PCAP_INITIALIZE_ERROR = 2
};

/**
 * @brief Contains TCP aggregated info.
 * 
 */
typedef struct tcp_connection_info 
{
    struct in_addr clientIP;      /* client ip addess */
    uint16_t clientPort;          /* client port */
    struct in_addr serverIP;      /* destination ip addess */
    uint16_t serverPort;          /* destination port */
    uint8_t lastFlag;             /* last tcp package flags */
    uint16_t retryCount;          /* tcp SYN retry count */
    uint8_t handshakeSucceeded;   /* SYN -> SYN/ACT -> ACT condition met */
} tcp_connection_info_t; 

/**
 * @brief Single Linked list that contains TCP connection info data
 * 
 */
typedef struct node
{
    tcp_connection_info_t connectionInfo;
    struct node* next;
} node_t;

// static variable that holds tcp connection info
static node_t* listHead = NULL;

static node_t* findNode(const tcp_connection_info_t* connectionInfo)
{
    if (listHead == NULL || connectionInfo == NULL)
    {
        return NULL;
    }

    node_t* currentHead = listHead;
    while (currentHead)
    {
        if (currentHead->connectionInfo.clientIP.s_addr == connectionInfo->clientIP.s_addr &&
            currentHead->connectionInfo.clientPort == connectionInfo->clientPort)
            break;

        currentHead = currentHead->next;
    }
      
    return currentHead;
}

/**
 * @brief Allocates and inserts a node to the end of the list or at the head of the list if head == NULL
 * 
 * @param connectionInfo 
 * @return node_t* pointer to the inserted node or NULL if malloc failed
 */
static node_t* insertNode(const tcp_connection_info_t* connectionInfo)
{
    if (listHead == NULL)
    {
        listHead = (node_t*)malloc(sizeof(node_t));

        // if malloc fails -> current package info is to be skipped
        // per current design, only SYN packages that are not present in the list 
        // lead to insertNode call
        if (listHead == NULL)
            return NULL;

        memcpy(&listHead->connectionInfo, connectionInfo, sizeof(tcp_connection_info_t));
        listHead->next = NULL;

        return listHead;
    }

    node_t* currentHead = listHead;
    while (currentHead->next != NULL)
    {
        currentHead = currentHead->next;
    }

    currentHead->next = (node_t*)malloc(sizeof(node_t));
    // if malloc fails -> current package info is to be skipped
    // per current design, only SYN packages that are not present in the list 
    // lead to insertNode call
    if (currentHead->next == NULL)
        return NULL;

    currentHead = currentHead->next;
    memcpy(&currentHead->connectionInfo, connectionInfo, sizeof(tcp_connection_info_t));
    currentHead->next = NULL;

    return currentHead;
}

static void deleteNode(node_t* node)
{
    if (listHead == NULL || node == NULL)
        return;

    node_t* currentNode = listHead;
    if (currentNode == node)
    {
        listHead = currentNode->next;
        free(currentNode);
        return;
    }


    while (currentNode && currentNode->next != node)
    {
        currentNode = currentNode->next;
    }

    if (currentNode)
        currentNode->next = node->next;
    free(node);
}

static void deleteList()
{
    while(listHead)
    {
        node_t* next = listHead->next;
        free(listHead);
        listHead = next;
    }

    listHead = NULL;
}

/**
 * @brief If a failed connection is repeated with the same source ip, destination ip and
 *        destination port (source ports can differ), add a count to the report.
 *        This function accumulates all retries across all records that has the same src ip, dst ip, dst port fields 
 * 
 * @param connectionInfo 
 * @return uint32_t 
 */
static uint32_t countOverallRetries(const tcp_connection_info_t* connectionInfo)
{
    uint32_t res = 0;

    node_t* currentHead = listHead;
    while (currentHead)
    {
        if (currentHead->connectionInfo.clientIP.s_addr == connectionInfo->clientIP.s_addr &&
            currentHead->connectionInfo.serverIP.s_addr == connectionInfo->serverIP.s_addr &&
            currentHead->connectionInfo.serverPort == connectionInfo->serverPort)
            res += currentHead->connectionInfo.retryCount;

        currentHead = currentHead->next;
    }
    
    return res;
}

/**
 * @brief Print current TCP session state with a proper retry counted according to AC1
 * 
 * @param connectionInfo 
 */
static void printSessionInfo(const tcp_connection_info_t* connectionInfo)
{ 
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(connectionInfo->clientIP), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(connectionInfo->serverIP), destIP, INET_ADDRSTRLEN);

    const u_int sourcePort = ntohs(connectionInfo->clientPort);
    const u_int destPort = ntohs(connectionInfo->serverPort);

    if (connectionInfo->handshakeSucceeded)
    {
        printf("%10s\t%s:%u -> %s:%u \n",
                "SUCCESS", sourceIP, sourcePort, destIP, destPort);
    }
    else
    {
        printf("%10s\t%s:%u -> %s:%u\t(retry count: %u)\n",
               "FAILED", sourceIP, sourcePort, destIP, destPort, countOverallRetries(connectionInfo));
    }
}

static void swapSrcDst(tcp_connection_info_t* connectionInfo)
{
    const struct in_addr clientIP = connectionInfo->clientIP;
    connectionInfo->clientIP = connectionInfo->serverIP;
    connectionInfo->serverIP = clientIP;

    const uint16_t clientPort = connectionInfo->clientPort;
    connectionInfo->clientPort = connectionInfo->serverPort;
    connectionInfo->serverPort = clientPort;
}

/**
 * @brief Updates tcp connection info list with a new data 
 * 
 * @param newConnectionInfo tcp connection info
 */
void updateConnectionInfoList(tcp_connection_info_t* newConnectionInfo)
{
    // SYN/ACK is sent by the server as a response on our SYN package
    // so the source IP == server IP in this case
    if (newConnectionInfo->lastFlag == (TH_SYN| TH_ACK))
        swapSrcDst(newConnectionInfo);

    node_t* existingSessionInfo = findNode(newConnectionInfo);

    if (existingSessionInfo == NULL && newConnectionInfo->lastFlag == TH_SYN)
    {
        // insert only nodes that start TCP handshake process
        existingSessionInfo = insertNode(newConnectionInfo);
    }
    else if (existingSessionInfo != NULL)
    {
        const uint8_t previousFlags = existingSessionInfo->connectionInfo.lastFlag;
        const uint8_t currentFlags =  newConnectionInfo->lastFlag;

        existingSessionInfo->connectionInfo.lastFlag = currentFlags;

        if (previousFlags == TH_SYN && currentFlags == TH_SYN)
        {
            // handshake fail. Retry package recieved
            existingSessionInfo->connectionInfo.retryCount += 1;
            existingSessionInfo->connectionInfo.handshakeSucceeded = 0;

            // update client host:port
            existingSessionInfo->connectionInfo.clientIP  = newConnectionInfo->clientIP;
            existingSessionInfo->connectionInfo.clientPort  = newConnectionInfo->clientPort;

            printSessionInfo(&existingSessionInfo->connectionInfo);
        }
        else if (previousFlags == (TH_SYN | TH_ACK) && currentFlags == TH_ACK)
        {
            // client confirmed recieved SYN/ACK.
            // handshake succeeded
            existingSessionInfo->connectionInfo.handshakeSucceeded = 1;
            printSessionInfo(&existingSessionInfo->connectionInfo);

            // no need to store this connection info anymore
            deleteNode(existingSessionInfo);
        }
    }
}

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
     
        updateConnectionInfoList(&info);
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