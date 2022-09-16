/**
 * @file tcp_connection_info.c
 * @author Mykhailo Lohvynenko (mikemike111997@gmail.com)
 * @brief contains implementation of functions to manipulate a list of aggragated tcp connections
 * @version 0.1
 * @date 2022-09-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */


#include "tcp_connection_info.h"


node_t* findNode(node_t** listHead, const tcp_connection_info_t* connectionInfo)
{
    if (listHead == NULL || *listHead == NULL || connectionInfo == NULL)
    {
        return NULL;
    }

    node_t* currentHead = *listHead;
    while (currentHead)
    {
        if (currentHead->connectionInfo.clientIP.s_addr == connectionInfo->clientIP.s_addr &&
            currentHead->connectionInfo.clientPort == connectionInfo->clientPort)
            break;

        currentHead = currentHead->next;
    }
      
    return currentHead;
}

node_t* insertNode(node_t** listHead, const tcp_connection_info_t* connectionInfo)
{
    if (*listHead == NULL)
    {
        *listHead = (node_t*)malloc(sizeof(node_t));

        // if malloc fails -> current package info is to be skipped
        // per current design, only SYN packages that are not present in the list 
        // lead to insertNode call
        if (*listHead == NULL)
            return NULL;

        memcpy(&(*listHead)->connectionInfo, connectionInfo, sizeof(tcp_connection_info_t));
        (*listHead)->next = NULL;

        return *listHead;
    }

    node_t* currentHead = *listHead;
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

void deleteNode(node_t** listHead, node_t* node)
{
    if (listHead == NULL || *listHead == NULL || node == NULL)
        return;

    node_t* currentNode = *listHead;
    if (currentNode == node)
    {
        *listHead = currentNode->next;
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

void deleteList(node_t** listHead)
{
    while(listHead && *listHead)
    {
        node_t* next = (*listHead)->next;
        free(*listHead);
        *listHead = next;
    }

    *listHead = NULL;
}

uint32_t countOverallRetries(node_t** listHead, const tcp_connection_info_t* connectionInfo)
{
    uint32_t res = 0;

    node_t* currentHead = *listHead;
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

void printSessionInfo(node_t** listHead, const tcp_connection_info_t* connectionInfo)
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
               "FAILED", sourceIP, sourcePort, destIP, destPort, countOverallRetries(listHead, connectionInfo));
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
 * @brief Upates retry count of a list entry that has a different source port number,
 *        but the same source host, destination host, destination port and the last package flag equal SYN
 * 
 * @param listHead 
 * @param connectionInfo 
 */
static void updateSiblingConnectionRetryCount(node_t** listHead, tcp_connection_info_t* connectionInfo)
{
    node_t* currentHead = *listHead;
    while (currentHead)
    {
        if (currentHead->connectionInfo.clientIP.s_addr == connectionInfo->clientIP.s_addr &&
            currentHead->connectionInfo.serverIP.s_addr == connectionInfo->serverIP.s_addr &&
            currentHead->connectionInfo.clientPort != connectionInfo->clientPort &&
            currentHead->connectionInfo.serverPort == connectionInfo->serverPort &&
            currentHead->connectionInfo.lastFlag == TH_SYN)
        {
            currentHead->connectionInfo.retryCount += connectionInfo->retryCount;
            break;
        }

        currentHead = currentHead->next;
    }
    
}

void updateConnectionInfoList(node_t** listHead, tcp_connection_info_t* newConnectionInfo)
{
    // SYN/ACK is sent by the server as a response on our SYN package
    // so the source IP == server IP in this case
    if (newConnectionInfo->lastFlag == (TH_SYN| TH_ACK))
        swapSrcDst(newConnectionInfo);

    node_t* existingSessionInfo = findNode(listHead, newConnectionInfo);

    if (existingSessionInfo == NULL && newConnectionInfo->lastFlag == TH_SYN)
    {
        // insert only nodes that start TCP handshake process
        existingSessionInfo = insertNode(listHead, newConnectionInfo);
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

            // // update client host:port
            // existingSessionInfo->connectionInfo.clientIP  = newConnectionInfo->clientIP;
            // existingSessionInfo->connectionInfo.clientPort  = newConnectionInfo->clientPort;

            printSessionInfo(listHead, &existingSessionInfo->connectionInfo);
        }
        else if (previousFlags == (TH_SYN | TH_ACK) && currentFlags == TH_ACK)
        {
            // client confirmed recieved SYN/ACK.
            // handshake succeeded
            existingSessionInfo->connectionInfo.handshakeSucceeded = 1;
            printSessionInfo(listHead, &existingSessionInfo->connectionInfo);

            updateSiblingConnectionRetryCount(listHead, &existingSessionInfo->connectionInfo);

            // no need to store this connection info anymore
            deleteNode(listHead, existingSessionInfo);
        }
    }
}

uint32_t countNodes(node_t* listHead)
{
    uint32_t res = 0;
    while(listHead)
    {
        ++res;
        listHead = listHead->next;
    }

    return res;
}