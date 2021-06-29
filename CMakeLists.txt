cmake_minimum_required(VERSION 3.0)

project (nethuns)

#
# Compiler options...
#

# set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -fsanitize=address -fsanitize=undefined")
# set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -fsanitize=address -fsanitize=undefined")

set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")

set (CMAKE_POSITION_INDEPENDENT_CODE ON)

option(NETHUNS_OPT_LIBPCAP              "Enable libpcap support" ON)
option(NETHUNS_OPT_BUILTIN_PCAP_READER  "Enable builtin pcap reader" OFF)
option(NETHUNS_OPT_TPACKET_V3           "Enable TPACKET v3 support" OFF)
option(NETHUNS_OPT_XDP                  "Enable XDP" OFF)
option(NETHUNS_OPT_NETMAP               "Enable Netmap support" OFF)

add_definitions(-D_GNU_SOURCE)

find_path(LIBPCAP_INCLUDE_DIR pcap/pcap.h)
find_library(LIBPCAP_LIBRARY NAMES libpcap.a)

include_directories(${LIBPCAP_INCLUDE_DIR})
include_directories(/usr/local/include/ src)

if (NETHUNS_OPT_XDP)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
endif()

#
# define the list of library to link...
#

set(NETHUNS_LIBS)

set(NETHUNS_SRC src/nethuns/nethuns.c
                src/nethuns/global.c)

if (NETHUNS_OPT_BUILTIN_PCAP_READER)
    	message("Nethuns: using built-in pcap reader")
	add_definitions(-DNETHUNS_USE_BUILTIN_PCAP_READER)
else()
    list(APPEND NETHUNS_LIBS ${LIBPCAP_LIBRARY})
    message("Nethuns: using libpcap to read files")
endif()

if (NETHUNS_OPT_TPACKET_V3)
    list(APPEND NETHUNS_SRC src/nethuns/sockets/tpacket_v3.c)
    message("Nethuns: tpcaket v3 ENABLED")
endif()

if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_SRC src/nethuns/sockets/netmap.c)
    message("Nethuns: netmap ENABLED")	
endif()

if (NETHUNS_OPT_XDP)

    message("Nethuns: xdp ENABLED")
    find_package(ZLIB)

    set(LIBBPF_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/libbpf.a)

    add_custom_target(
  	build_libbpf ALL
  	COMMAND ${CMAKE_MAKE_PROGRAM}
  	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
	COMMENT "Libbpf makefile target" )

    add_library(libbpf STATIC IMPORTED)

    set_property(TARGET libbpf APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
    set_target_properties(libbpf PROPERTIES IMPORTED_LOCATION_NOCONFIG "${LIBBPF_LIBRARY}")

    add_dependencies(libbpf build_libbpf)

    list(APPEND NETHUNS_SRC src/nethuns/sockets/xdp.c)
    list(APPEND NETHUNS_SRC src/nethuns/sockets/xsk_ext.c)

    list(APPEND NETHUNS_LIBS libbpf)
    list(APPEND NETHUNS_LIBS -lelf)
    list(APPEND NETHUNS_LIBS ZLIB::ZLIB)

endif()

if (NETHUNS_OPT_LIBPCAP)
    message("Nethuns: libpcap ENABLEd")
    list(APPEND NETHUNS_SRC src/nethuns/sockets/libpcap.c)
    list(APPEND NETHUNS_LIBS ${LIBPCAP_LIBRARY})
endif()

add_library(nethuns STATIC ${NETHUNS_SRC})

target_link_libraries(nethuns PRIVATE ${NETHUS_LIBS})

install(TARGETS nethuns DESTINATION /usr/local/lib)

install(DIRECTORY src/nethuns/ 	   	DESTINATION /usr/local/include/nethuns FILES_MATCHING PATTERN "*.h" PATTERN src/nethuns/sockets/xdp EXCLUDE)
install(DIRECTORY libbpf/src/      	DESTINATION /usr/local/include/nethuns/sockets/xdp FILES_MATCHING PATTERN "*.h" )
install(DIRECTORY libbpf/include/uapi/  DESTINATION /usr/local/include/nethuns/sockets/xdp FILES_MATCHING PATTERN "*.h" )
if (NETHUNS_OPT_XDP)
    install(FILES     libbpf/src/libbpf.a   DESTINATION /usr/local/lib/)
endif()
