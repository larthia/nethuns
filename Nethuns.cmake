cmake_minimum_required(VERSION 2.8)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "libpcap" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS libpcap tpacket3 netmap)

option(NETHUNS_NATIVE_PCAPFILE_READER "Nethuns use native pcapfile reader instead of libpcap" OFF)

if (NETHUNS_NATIVE_PCAPFILE_READER)
    add_definitions(-DNETHUNS_USE_NATIVE_PCAPFILE_READER)
endif()

if (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")

    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_USE_DEVPCAP)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")

    message ("Nethuns: native TPACKET_v3 enabled!")
    add_definitions(-DNETHUNS_USE_TPACKET_V3)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")

    message ("Nethuns: netmap socket enabled!")
    add_definitions(-DNETHUNS_USE_NETMAP)
    
endif()



