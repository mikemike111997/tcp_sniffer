#include <tcp_connection_info.h>
#include <check.h>
#include <stdlib.h>


START_TEST(tcp_connection_info_list)
{
    node_t* head = NULL;
    ck_assert_ptr_eq(head, NULL);

    tcp_connection_info_t newInfo  = {
        .clientIP.s_addr = 10,
        .clientPort = 10,
        .serverIP.s_addr = 10,
        .serverPort = 10
    };

    insertNode(&head, &newInfo);
    ck_assert_ptr_ne(head, NULL);
    ck_assert_uint_eq(countNodes(head), 1);

    deleteNode(&head, head);
    ck_assert_ptr_eq(head, NULL);

    // insert 2 nodes to an empty list
    {
        insertNode(&head, &newInfo);
        ck_assert_uint_eq(countNodes(head), 1);

        insertNode(&head, &newInfo);
        ck_assert_uint_eq(countNodes(head), 2);

        ck_assert_ptr_ne(head, NULL);
        ck_assert_ptr_ne(head->next, NULL);
        ck_assert_ptr_eq(head->next->next, NULL);
    }

    // insert specific node and find it
    {
        tcp_connection_info_t node = {
            .clientIP.s_addr = 30,
            .clientPort = 30,
            .serverIP.s_addr = 30,
            .serverPort = 30
        };

        insertNode(&head, &node);
        ck_assert_uint_eq(countNodes(head), 3);

        node_t* foundNode = findNode(&head, &node);
        ck_assert_ptr_ne(foundNode, NULL);
        ck_assert_ptr_eq(foundNode->next, NULL);
        ck_assert_uint_eq(foundNode->connectionInfo.clientIP.s_addr, node.clientIP.s_addr);
    }

    deleteList(&head);

} END_TEST

START_TEST(update_connection_info_list)
{
    node_t* head = NULL;
    ck_assert_ptr_eq(head, NULL);

    tcp_connection_info_t info1 = {
        .clientIP.s_addr = 100,
        .clientPort = 100,
        .serverIP.s_addr = 200,
        .serverPort = 200,
        .handshakeSucceeded = 0,
        .retryCount = 0,
        .lastFlag = 0
    };
    updateConnectionInfoList(&head, &info1);

    // lastFlag is empty, only records with SYN flag set are inserted.
    node_t* ptrNode1 = findNode(&head, &info1);
    ck_assert_uint_eq(countNodes(head), 0);
    ck_assert_ptr_eq(ptrNode1, NULL);
    ck_assert_ptr_eq(head, NULL);

    info1.lastFlag = TH_SYN;
    updateConnectionInfoList(&head, &info1);
    ck_assert_ptr_ne(head, NULL);
    ck_assert_uint_eq(countNodes(head), 1);

    ptrNode1 = findNode(&head, &info1);
    ck_assert_ptr_ne(ptrNode1, NULL);

    for (size_t i = 0; i < 10; ++i)
    {
        info1.lastFlag = TH_SYN;
        updateConnectionInfoList(&head, &info1);
        ck_assert_uint_eq(ptrNode1->connectionInfo.lastFlag, TH_SYN);
        ck_assert_uint_eq(countNodes(head), 1);
        ck_assert_uint_eq(ptrNode1->connectionInfo.retryCount, i + 1);
    }

    // add another node with a different source ip, but the same host ip
    tcp_connection_info_t info2;
    memcpy(&info2, &info1, sizeof(tcp_connection_info_t));
    info2.retryCount = 0;
    info2.clientPort = 101;

    updateConnectionInfoList(&head, &info2);
    ck_assert_uint_eq(countNodes(head), 2);

    node_t* ptrNode2 = findNode(&head, &info2);
    ck_assert_ptr_ne(ptrNode2, NULL);

    // it's a design decision that all source host:port entities in the list
    // have their own retry counters
    ck_assert_uint_eq(ptrNode2->connectionInfo.retryCount, 0);

    for (size_t i = 0; i < 10; ++i)
    {
        info2.lastFlag = TH_SYN;
        updateConnectionInfoList(&head, &info2);
        ck_assert_uint_eq(ptrNode2->connectionInfo.lastFlag, TH_SYN);
        ck_assert_uint_eq(countNodes(head), 2);
        ck_assert_uint_eq(ptrNode2->connectionInfo.retryCount, i + 1);
    }
    
    // but in the output an accumulated retry counter is used
    const uint32_t accumulatedRetriesCount1 = countOverallRetries(&head, &ptrNode1->connectionInfo);
    const uint32_t accumulatedRetriesCount2 = countOverallRetries(&head, &ptrNode2->connectionInfo);
    ck_assert_uint_eq(accumulatedRetriesCount1, accumulatedRetriesCount2);
    ck_assert_uint_ne(countOverallRetries(&head, &ptrNode2->connectionInfo), ptrNode1->connectionInfo.retryCount);
    ck_assert_uint_eq(countOverallRetries(&head, &ptrNode2->connectionInfo),
                      ptrNode1->connectionInfo.retryCount + ptrNode2->connectionInfo.retryCount);

    // if a SYN/ACT package recieved from server after a SYN package is sent from client, we are still not considering
    // this tcp handshake as a successful one
    {
        tcp_connection_info_t responseInfo2 = {
            .clientIP.s_addr = info2.serverIP.s_addr,
            .clientPort = info2.serverPort,
            .serverIP.s_addr = info2.clientIP.s_addr,
            .serverPort = info2.clientPort,
            .lastFlag = TH_SYN | TH_ACK
        };

        updateConnectionInfoList(&head, &responseInfo2);
    }
    ck_assert_uint_eq(ptrNode2->connectionInfo.handshakeSucceeded, 0);
    ck_assert_uint_eq(countNodes(head), 2);
    ck_assert_ptr_eq(head->next, ptrNode2);
    ck_assert_uint_eq(ptrNode2->connectionInfo.lastFlag, TH_SYN | TH_ACK);

    // only after client send ACT to the server (after client got ACT/SYN) tcp handshake marks as succesfull 
    // and is removed from the list
    info2.lastFlag = TH_ACK;
    updateConnectionInfoList(&head, &info2);
    ck_assert_uint_eq(countNodes(head), 1);

    ptrNode2 = findNode(&head, &info2);
    ck_assert_ptr_eq(ptrNode2, NULL);

    // now there's only one record in the list
    ck_assert_uint_eq(countNodes(head), 1);
    ck_assert_ptr_ne(head, NULL);
    ck_assert_ptr_eq(head->next, NULL);

    // and it's retry count is equal to the overall retry count to that src host, dst host, dst port
    ck_assert_uint_eq(head->connectionInfo.retryCount, accumulatedRetriesCount1);

    deleteList(&head);

} END_TEST

Suite* suite(void)
{
    Suite* s = suite_create("Linked List");
    TCase* tc_core = tcase_create("List functionality");

    tcase_add_test(tc_core, tcp_connection_info_list);
    tcase_add_test(tc_core, update_connection_info_list);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int no_failed = 0;                   

    Suite* s = suite();                   
    SRunner* runner = srunner_create(s);          

    srunner_run_all(runner, CK_NORMAL);  

    no_failed = srunner_ntests_failed(runner); 
    srunner_free(runner);                      
    return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;  
}