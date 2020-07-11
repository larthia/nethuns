cmake_minimum_required(VERSION 2.8)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "libpcap" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS libpcap tpacket3 xdp netmap)

option(NETHUNS_BUILTIN_PCAP_READER "Nethuns use built-in pcap reader (instead of libpcap)" OFF)

if (NETHUNS_BUILTIN_PCAP_READER OR (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp"))
	set(NETHUNS_BUILTIN_PCAP_READER ON CACHE BOOL ON FORCE)
	add_definitions(-DNETHUNS_USE_BUILTIN_PCAP_READER)
endif()

if (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")

    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_USE_DEVPCAP)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")

    message ("Nethuns: TPACKET_v3 enabled!")
    add_definitions(-DNETHUNS_USE_TPACKET_V3)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp")

    message ("Nethuns: AF_XDP enabled!")
    add_definitions(-DNETHUNS_USE_XDP)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")

    message ("Nethuns: netmap socket enabled!")
    add_definitions(-DNETHUNS_USE_NETMAP)
    
endif()



