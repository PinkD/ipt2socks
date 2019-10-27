cmake_minimum_required(VERSION 2.10)
project(ipt2socks)

set(CMAKE_C_STANDARD 99)

add_executable(
        ipt2socks
        ipt2socks.c
        lrucache.c
        netutils.c
)

target_link_libraries(ipt2socks uv pthread)
