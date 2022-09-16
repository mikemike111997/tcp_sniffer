cmake_minimum_required(VERSION 3.16.3 FATAL_ERROR)

project(tcp_analyzer C)


if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
else()
    set (CMAKE_C_STANDARD_REQUIRED 11)
endif()

add_compile_options(-Wall -Wextra -pedantic -Werror)
add_compile_options(-Wno-error=unused-parameter)

add_library(tcp_connection_info OBJECT tcp_connection_info.c)

add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} pcap tcp_connection_info)

find_library(CHECK_LIB check)
if(NOT CHECK_LIB)
    message(FATAL_ERROR "lua library not found")
else()
    include(CTest)
    add_subdirectory(tests)
endif()
