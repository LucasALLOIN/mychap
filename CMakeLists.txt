cmake_minimum_required(VERSION 3.0)
project(NWP_mychap_2018)

set(CMAKE_C_STANDARD 99)

include_directories(includes)

add_executable(client sources/main.c sources/args.c sources/utils.c sources/udp_socket_builder.c sources/udp_manager.c)
target_link_libraries(client crypto)