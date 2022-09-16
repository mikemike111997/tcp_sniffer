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


struct TCPConnectionInfo
{
    // clientIP:clientPort is a session ID
    struct in_addr clientIP;
    uint16_t clientPort;

    struct in_addr serverIP;
    uint16_t serverPort;

    uint8_t lastFlag;

    uint16_t retryCount;

    uint8_t handshakeSucceeded; 
};


typedef struct node
{
    struct TCPConnectionInfo connectionInfo;
    struct node* next;
} node_t;

static node_t* listHead = NULL;

node_t* findNode(const struct TCPConnectionInfo* connectionInfo)
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

node_t* insertNode(const struct TCPConnectionInfo* connectionInfo)
{
    if (listHead == NULL)
    {
        listHead = (node_t*)malloc(sizeof(node_t));
        memcpy(&listHead->connectionInfo, connectionInfo, sizeof(struct TCPConnectionInfo));
        listHead->next = NULL;

        return listHead;
    }

    node_t* currentHead = listHead;
    while (currentHead->next != NULL)
    {
        currentHead = currentHead->next;
    }

    currentHead->next = (node_t*)malloc(sizeof(node_t));
    currentHead = currentHead->next;
    memcpy(&currentHead->connectionInfo, connectionInfo, sizeof(struct TCPConnectionInfo));
    currentHead->next = NULL;

    return currentHead;
}

void deleteNode(node_t* node)
{
    if (listHead == NULL || node == NULL)
        return;

    node_t* currentNode = listHead;
    if (currentNode == node)
    {
        if (currentNode->next)
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

void deleteList()
{
    while(listHead)
    {
        node_t* next = listHead->next;
        free(listHead);
        listHead = next;
    }

    listHead = NULL;
}

static void printSessionInfo(const struct TCPConnectionInfo* connectionInfo)
{ 
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(connectionInfo->clientIP), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(connectionInfo->serverIP), destIP, INET_ADDRSTRLEN);

    const u_int sourcePort = ntohs(connectionInfo->clientPort);
    const u_int destPort = ntohs(connectionInfo->serverPort);

    if (connectionInfo->handshakeSucceeded)
    {
        printf("SUCCESS                   %s:%u -> %s:%u \n",
                sourceIP, sourcePort, destIP, destPort);
    }
    else
    {
        printf("FAILED (retry count: %u)  %s:%u -> %s:%u \n",
               (*connectionInfo).retryCount, sourceIP, sourcePort, destIP, destPort);
    }
}

void swapSrcDst(struct TCPConnectionInfo* newConnectionInfo)
{
    const struct in_addr clientIP = newConnectionInfo->clientIP;
    newConnectionInfo->clientIP = newConnectionInfo->serverIP;
    newConnectionInfo->serverIP = clientIP;

    const uint16_t clientPort = newConnectionInfo->clientPort;
    newConnectionInfo->clientPort = newConnectionInfo->serverPort;
    newConnectionInfo->serverPort = clientPort;
}

void updateSessionInfo(struct TCPConnectionInfo* newConnectionInfo)
{
    node_t* sessionInfo = findNode(newConnectionInfo);

    if (sessionInfo == NULL && newConnectionInfo->lastFlag == TH_SYN)
    {
        // insert only nodes that start TCP handshake process
        sessionInfo = insertNode(newConnectionInfo);
    }
    else if (sessionInfo != NULL)
    {
        const uint8_t previousFlags = sessionInfo->connectionInfo.lastFlag;
        const uint8_t currentFlags =  newConnectionInfo->lastFlag;

        sessionInfo->connectionInfo.lastFlag = currentFlags;

        if (previousFlags == TH_SYN && currentFlags == TH_SYN)
        {
            // handshake fail. Retry package recieved
            sessionInfo->connectionInfo.retryCount += 1;
            sessionInfo->connectionInfo.handshakeSucceeded = 0;
            printSessionInfo(&sessionInfo->connectionInfo);
        }
        else if (previousFlags == (TH_SYN | TH_ACK) && currentFlags == TH_ACK)
        {
            // client confirmed recieved SYN/ACK.
            // handshake succeeded
            sessionInfo->connectionInfo.handshakeSucceeded = 1;
            printSessionInfo(&sessionInfo->connectionInfo);

            // no need to store this connection info anymore
            deleteNode(sessionInfo);
        }
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
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

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);


    const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    const u_int sourcePort = ntohs(tcpHeader->source);
    const u_int destPort = ntohs(tcpHeader->dest);


    char resBuffer[1024];
    snprintf(resBuffer, sizeof(resBuffer), "%s:%d -> %s:%d; ack_seq: %u; seq_num: %u",
             sourceIP, sourcePort, destIP, destPort, tcpHeader->ack_seq, tcpHeader->th_seq);

    if (tcpHeader->th_flags & (TH_SYN | TH_ACK))
    {
        struct TCPConnectionInfo info;
        memset(&info, '\0', sizeof(struct TCPConnectionInfo)); 

        info.clientIP = ipHeader->ip_src;
        info.clientPort = tcpHeader->source;
        info.serverIP = ipHeader->ip_dst;
        info.serverPort = tcpHeader->dest;
        info.lastFlag = tcpHeader->th_flags;

        if (info.lastFlag == (TH_SYN| TH_ACK))
            swapSrcDst(&info);
        
        updateSessionInfo(&info);
    }
}


int main(int argC, char* argV[])
{
    if (argC != 2)
    {
        fprintf(stderr, "Error: expected device name as an input param");
        return -1;
    }

    char* dev = argV[1];
    printf("Device name is %s\n", dev);

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // filter trafic
    struct bpf_program fp;  /* The compiled filter expression */
    char filter_exp[] = "tcp "; /* The filter expression */
    bpf_u_int32 mask = 0;   /* The netmask of our sniffing device */
    bpf_u_int32 net = 0;        /* The IP of our sniffing device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    else
    {
        printf("Dev: %s; net: %u; mask: %u\n", dev, net, mask);
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, packetHandler, NULL);

    /* And close the session */
    pcap_close(handle);

    pcap_freecode(&fp);

    deleteList(&listHead);

    return 0;
}