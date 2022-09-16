enable_testing()

add_executable(tests test.c)
add_link_options(subunit)
target_link_libraries(tests check tcp_connection_info m pthread rt subunit)
target_include_directories(tests PRIVATE ..)

add_test(NAME UnitTest COMMAND tests)

find_program(MEMORYCHECK_COMMAND valgrind )
if (MEMORYCHECK_COMMAND)
    add_test(NAME UnitTestWithValgrind
    COMMAND valgrind --leak-check=full --show-leak-kinds=all -s --error-exitcode=1 ./tests)
endif()