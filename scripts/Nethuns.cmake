# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.10)

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

set(NETHUNS_CAPTURE_SOCKET ${FIRST_SOCKET} CACHE STRING "Nethuns underlying socket")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS ${NETHUNS_SOCK_LIST})

set(NETHUNS_LIBRARY_DIRS)
set(NETHUNS_INCLUDE_DIRS)

#
# Nethuns installation...

if (USE_LOCAL_NETHUNS)
    message ("Nethuns: using local installation")
    list(APPEND NETHUNS_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/include)
    list(APPEND NETHUNS_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/libs/Nethuns/libnethuns.a)
    list(APPEND NETHUNS_LIBBPF_LIBRARY libbpf/src/libbpf.a) 
else()
    message ("Nethuns: using system installation")
    list(APPEND NETHUNS_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include)
    list(APPEND NETHUNS_LIBRARY_DIRS ${CMAKE_INSTALL_PREFIX}/lib/libnethuns.a)
    find_library(NETHUNS_LIBBPF_LIBRARY bpf)
endif()

#
# detecting libpcap installation...

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(NETHUNS_LIBPCAP_LIBRARY NAMES pcap PATHS "/usr/local/opt/libpcap/lib" "/opt/homebrew/opt/libpcap/lib" NO_DEFAULT_PATH)
    find_path(NETHUNS_LIBPCAP_INCLUDE NAMES pcap/pcap.h PATHS "/usr/local/opt/libpcap/include/" "/opt/homebrew/opt/libpcap/include" NO_DEFAULT_PATH)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    find_library(NETHUNS_LIBPCAP_LIBRARY pcap PATHS "/usr/local/lib")
    find_path(NETHUNS_LIBPCAP_INCLUDE NAMES pcap/pcap.h PATHS "/usr/local/include")
else()
    message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} platform not supported!")
endif()


list(APPEND NETHUNS_INCLUDE_DIRS ${NETHUNS_LIBPCAP_INCLUDE})
list(APPEND NETHUNS_LIBRARY_DIRS ${NETHUNS_LIBPCAP_LIBRARY})

#
# detecting other libraries...

find_package(ZLIB)
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
    list(APPEND NETHUNS_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include/nethuns/sockets/xdp/)
    list(APPEND NETHUNS_LIBRARY_DIRS ${NETHUNS_LIBBPF_LIBRARY})
    list(APPEND NETHUNS_LIBRARY_DIRS ${NETHUNS_LIBELF_LIBRARY})
    list(APPEND NETHUNS_LIBRARY_DIRS ZLIB::ZLIB)
endif()

if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_LIBRARY_DIRS ${NETHUNS_NETMAP_LIBRARY})
endif()
