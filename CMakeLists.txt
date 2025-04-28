cmake_minimum_required(VERSION 3.10)
project(toralize C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -g -O2")
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

add_library(toralize SHARED
    toralize.c
    socks5_client.c
)

target_link_libraries(toralize
    dl
    pthread
)

# create test executable
add_executable(socks5_test
    socks5_example.c
    socks5_client.c
)

install(TARGETS toralize
    LIBRARY DESTINATION /usr/local/lib
)
install(FILES toralize.conf
    DESTINATION /etc
)
