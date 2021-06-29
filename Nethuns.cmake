cmake_minimum_required(VERSION 3.0)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "libpcap" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS libpcap tpacket3 xdp netmap)

set(NETHUNS_LIBS)
    
find_library(LIBPCAP_LIBRARY pcap)

list(APPEND NETHUNS_LIBS nethuns)
list(APPEND NETHUNS_LIBS ${LIBPCAP_LIBRARY})

if (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")
    message ("Nethuns: TPACKET_v3 enabled!")
    add_definitions(-DNETHUNS_SOCKET=3)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp")
    message ("Nethuns: AF_XDP enabled!")
    add_definitions(-DNETHUNS_SOCKET=2)
    include_directories(BEFORE /usr/local/include/nethuns/sockets/xdp/)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")
    message ("Nethuns: netmap socket enabled!")
    add_definitions(-DNETHUNS_SOCKET=1)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")
    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_SOCKET=0)
endif()
