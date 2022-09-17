cmake_minimum_required(VERSION 3.16.3 FATAL_ERROR)

project(tcp_analyzer VERSION 0.1.1  LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-Wall -Wextra -pedantic -Werror)
add_compile_options(-Wno-error=unused-parameter)

add_library(tcp_connection_info OBJECT tcp_connection_info.c)
add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} pcap tcp_connection_info)

install(TARGETS ${PROJECT_NAME}
        DESTINATION bin
        COMPONENT ${PROJECT_NAME})

find_library(CHECK_LIB check)
if(NOT CHECK_LIB)
    message(FATAL_ERROR "lua library not found")
else()
    include(CTest)
    add_subdirectory(tests)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DebPacking)