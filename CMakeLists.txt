cmake_minimum_required(VERSION 2.4)

project (nethuns)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion")


include_directories(src)

add_definitions(-D_GNU_SOURCE)

add_library(nethuns_static STATIC src/nethuns.c)
add_library(nethuns SHARED src/nethuns.c)

add_executable(test-nethuns test/main.c)

link_directories(${nethuns_BINARY_DIR})

target_link_libraries(test-nethuns nethuns)


install_targets(/lib nethuns)
install_targets(/lib nethuns_static)

install_files(/include/nethuns FILES src/nethuns.h)
