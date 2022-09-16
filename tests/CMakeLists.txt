enable_testing()


add_executable(tests test.c)
add_link_options(subunit)
target_link_libraries(tests check tcp_connection_info m pthread rt subunit)
target_include_directories(tests PRIVATE ..)

add_test (NAME MyTest COMMAND tests)