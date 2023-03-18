# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.0)

#
# Nethuns options...
#

set(NETHUNS_OPT_LIBPCAP     @NETHUNS_OPT_LIBPCAP@)
set(NETHUNS_OPT_XDP         @NETHUNS_OPT_XDP@)
set(NETHUNS_OPT_NETMAP      @NETHUNS_OPT_NETMAP@)
set(NETHUNS_OPT_TPACKET_V3  @NETHUNS_OPT_TPACKET_V3@)

set(NETHUNS_SOCK_LIST)

if (NETHUNS_OPT_LIBPCAP)
    list(APPEND NETHUNS_SOCK_LIST "libpcap")
endif()
if (NETHUNS_OPT_XDP)
    list(APPEND NETHUNS_SOCK_LIST "xdp")
endif()
if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_SOCK_LIST "netmap")
endif()
if (NETHUNS_OPT_TPACKET_V3)
    list(APPEND NETHUNS_SOCK_LIST "tpacket3")
endif()

list(GET NETHUNS_SOCK_LIST 0 FIRST_SOCKET)

message ("Nethuns: Available sockets: ${NETHUNS_SOCK_LIST}, default: ${FIRST_SOCKET}")

set(NETHUNS_CAPTURE_SOCKET ${FIRST_SOCKET} CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS ${NETHUNS_SOCK_LIST})

set(NETHUNS_LIBS)

set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/usr/local/include" "/opt/include" "/opt/homebrew/include" "/opt/homebrew/opt/libpcap/include")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "/usr/local/lib" "/opt/lib" "/opt/homebrew/lib" "/opt/homebrew/opt/libpcap/lib")

find_library(LIBPCAP_LIBRARY pcap)
find_library(LIBBPF_LIBRARY bpf)
find_library(LIBELF_LIBRARY elf)
find_library(LIBNETMAP_LIBRARY netmap)
find_package(ZLIB)

list(APPEND NETHUNS_LIBS nethuns)
list(APPEND NETHUNS_LIBS ${LIBPCAP_LIBRARY})

if (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")
    message ("Nethuns: TPACKET_v3 enabled!")
    add_definitions(-DNETHUNS_SOCKET=3)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp")
    message ("Nethuns: AF_XDP enabled!")
    add_definitions(-DNETHUNS_SOCKET=2)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")
    message ("Nethuns: netmap socket enabled!")
    add_definitions(-DNETHUNS_SOCKET=1)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")
    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_SOCKET=0)
endif()

if (NETHUNS_OPT_XDP)
    include_directories(BEFORE /usr/local/include/nethuns/sockets/xdp/)
    list(APPEND NETHUNS_LIBS ${LIBBPF_LIBRARY})
    list(APPEND NETHUNS_LIBS ${LIBELF_LIBRARY})
    list(APPEND NETHUNS_LIBS ZLIB::ZLIB)
endif()

if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_LIBS ${LIBNETMAP_LIBRARY})
endif()
