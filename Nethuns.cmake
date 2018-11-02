cmake_minimum_required(VERSION 2.8)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "tpacket3" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS tpacket3 libpcap)


if (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")

    message ("Nethuns: native TPACKET_v3 enabled!")
    add_definitions(-DNETHUNS_USE_TPACKET_V3)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")

    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_USE_DEVPCAP)

endif()



