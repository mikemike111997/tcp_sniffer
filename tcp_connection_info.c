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
