#include <tcp_connection_info.h>
#include <check.h>
#include <stdlib.h>


START_TEST(tcp_connection_info_list)
{
    node_t* head = NULL;
    ck_assert_ptr_eq(head, NULL);

    tcp_connection_info_t newInfo;
    insertNode(&head, &newInfo);
    ck_assert_ptr_ne(head, NULL);

    deleteNode(&head, head);
    ck_assert_ptr_eq(head, NULL);

    // insert 2 nodes to an empty list
    {
        insertNode(&head, &newInfo);
        insertNode(&head, &newInfo);

        ck_assert_ptr_ne(head, NULL);
        ck_assert_ptr_ne(head->next, NULL);
        ck_assert_ptr_eq(head->next->next, NULL);
    }

    // insert specific node and find it
    {
        tcp_connection_info_t node = {
            .clientIP.s_addr = 30
        };

        insertNode(&head, &node);
        node_t* foundNode = findNode(&head, &node);
        ck_assert_ptr_ne(foundNode, NULL);
        ck_assert_ptr_eq(foundNode->next, NULL);
        ck_assert_uint_eq(foundNode->connectionInfo.clientIP.s_addr, node.clientIP.s_addr);
    }


} END_TEST

Suite *money_suite(void)
{
    Suite* s = suite_create("Linked List");
    TCase* tc_core = tcase_create("List functionality");

    tcase_add_test(tc_core, tcp_connection_info_list);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int no_failed = 0;                   

    Suite* s = money_suite();                   
    SRunner* runner = srunner_create(s);          

    srunner_run_all(runner, CK_NORMAL);  

    no_failed = srunner_ntests_failed(runner); 
    srunner_free(runner);                      
    return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;  
}