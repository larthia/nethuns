# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.20)

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

set(NETHUNS_LIBRARIES)
set(NETHUNS_INCLUDE_PATHS)

list(APPEND NETHUNS_INCLUDE_PATHS /usr/local/include)

if (APPLE)
    find_library(NETHUNS_LIBPCAP_LIBRARY NAMES libpcap.a PATHS "/usr/local/opt/libpcap/lib" "/opt/homebrew/opt/libpcap/lib" NO_DEFAULT_PATH)
    find_path(NETHUNS_LIBPCAP_INCLUDE NAMES pcap/pcap.h PATHS "/usr/local/opt/libpcap/include/" "/opt/homebrew/opt/libpcap/include" NO_DEFAULT_PATH)
elseif(LINUX)
    find_library(NETHUNS_LIBPCAP_LIBRARY  libpcap.a PATHS "/usr/local/lib")
    find_path(NETHUNS_LIBPCAP_INCLUDE NAMES pcap/pcap.h PATHS "/usr/local/include")
endif()

find_package(ZLIB)

list(APPEND NETHUNS_LIBRARIES /usr/local/lib/libnethuns.a)
list(APPEND NETHUNS_LIBRARIES ${NETHUNS_LIBPCAP_LIBRARY})
list(APPEND NETHUNS_INCLUDE_PATHS ${NETHUNS_LIBPCAP_INCLUDE})

find_library(NETHUNS_LIBBPF_LIBRARY bpf)
find_library(NETHUNS_LIBELF_LIBRARY elf)
find_library(NETHUNS_NETMAP_LIBRARY netmap)

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
    list(APPEND NETHUNS_INCLUDE_PATHS /usr/local/include/nethuns/sockets/xdp/)
    list(APPEND NETHUNS_LIBRARIES ${NETHUNS_LIBBPF_LIBRARY})
    list(APPEND NETHUNS_LIBRARIES ${NETHUNS_LIBELF_LIBRARY})
    list(APPEND NETHUNS_LIBRARIES ZLIB::ZLIB)
endif()

if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_LIBRARIES ${NETHUNS_NETMAP_LIBRARY})
endif()
