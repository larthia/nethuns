cmake_minimum_required(VERSION 3.0)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "libpcap" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS libpcap tpacket3 xdp netmap)

set(NETHUNS_LIBS)
    
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
    include_directories(BEFORE /usr/local/include/nethuns/sockets/xdp/)
    list(APPEND NETHUNS_LIBS ${LIBBPF_LIBRARY})
    list(APPEND NETHUNS_LIBS ${LIBELF_LIBRARY})
    list(APPEND NETHUNS_LIBS ZLIB::ZLIB)
    	
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")
    message ("Nethuns: netmap socket enabled!")
    add_definitions(-DNETHUNS_SOCKET=1)
    list(APPEND NETHUNS_LIBS ${LIBNETMAP_LIBRARY})

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")
    message ("Nethuns: basic libpcap enabled!")
    add_definitions(-DNETHUNS_SOCKET=0)
endif()
