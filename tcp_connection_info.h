/**
 * @file tcp_connection_info.h
 * @author Mykhailo Lohvynenko (mikemike111997@gmail.com)
 * @brief contains declaration of structures and functions
 *        to manipulate a list of aggragated tcp connections  
 * @version 0.1
 * @date 2022-09-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#pragma once


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

node_t* findNode(node_t** listHead, const tcp_connection_info_t* connectionInfo);

/**
 * @brief Allocates and inserts a node to the end of the list or at the head of the list if head == NULL
 * 
 * @param connectionInfo 
 * @return node_t* pointer to the inserted node or NULL if malloc failed
 */
node_t* insertNode(node_t** listHead, const tcp_connection_info_t* connectionInfo);

/**
 * @brief deletees a node from a list
 * 
 * @param listHead head of list
 * @param node node to be deleted
 */
void deleteNode(node_t** listHead, node_t* node);

/**
 * @brief removes all items from the list and frees memory
 * 
 * @param listHead 
 */
void deleteList(node_t** listHead);

/**
 * @brief Print current TCP session state with a proper retry counted according to AC1
 * 
 * @param connectionInfo 
 */
void printSessionInfo(node_t** listHead, const tcp_connection_info_t* connectionInfo);

/**
 * @brief Updates tcp connection info list with a new data 
 * 
 * @param newConnectionInfo tcp connection info
 */
void updateConnectionInfoList(node_t** listHead, tcp_connection_info_t* newConnectionInfo);

/**
 * @brief If a failed connection is repeated with the same source ip, destination ip and
 *        destination port (source ports can differ), add a count to the report.
 *        This function accumulates all retries across all records that has the same src ip, dst ip, dst port fields 
 * 
 * @param connectionInfo 
 * @return uint32_t 
 */
uint32_t countOverallRetries(node_t** listHead, const tcp_connection_info_t* connectionInfo);

/**
 * @brief Count number of nodes in the list
 * 
 * @param listHead pointer to the list head
 * @return uint32_t size of list
 */
uint32_t countNodes(node_t* listHead);
