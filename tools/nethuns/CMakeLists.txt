# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.0)

project (nethuns-dump)

include(/usr/local/share/nethuns/Nethuns.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# Compiler options...
#

string(FIND "${CMAKE_CXX_COMPILER_ID}" "Clang" CLANG_SUBSTRING_INDEX)
if ("${CLANG_SUBSTRING_INDEX}" GREATER -1)
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -fomit-frame-pointer -Wall -Wextra -Wshadow")
else()
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
endif()

set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/usr/local/include" "/opt/include" "/opt/homebrew/include" "/opt/homebrew/opt/libpcap/include")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "/usr/local/lib" "/opt/lib" "/opt/homebrew/lib" "/opt/homebrew/opt/libpcap/lib")

find_library(LIBPCAP_LIBRARY NAMES libpcap.a)
find_path(LIBPCAP_INCLUDE_DIR pcap/pcap.h)

include_directories(${LIBPCAP_INCLUDE_DIR})
include_directories(/usr/local/include/ . ../src)

link_directories(/usr/local/lib)

add_executable(nethuns-dump src/main.c
                            src/options.c
                            src/dump.c
                            src/run.c)

target_link_libraries(nethuns-dump ${NETHUNS_LIBS} ${LIBPCAP_LIBRARY} -pthread)
