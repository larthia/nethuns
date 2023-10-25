# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.10)

project (nethuns)

#
# Compiler options...
#

string(FIND "${CMAKE_CXX_COMPILER_ID}" "Clang" CLANG_SUBSTRING_INDEX)
if ("${CLANG_SUBSTRING_INDEX}" GREATER -1)
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -Wno-unused-function -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wno-unused-function -std=c++17 -fomit-frame-pointer -Wall -Wextra -Wshadow")
else()
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -Wno-unused-function -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wno-unused-function -std=c++17 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
endif()


set (CMAKE_POSITION_INDEPENDENT_CODE ON)

option(NETHUNS_OPT_LIBPCAP              "Enable libpcap support" ON)
option(NETHUNS_OPT_BUILTIN_PCAP_READER  "Enable builtin pcap reader" OFF)
option(NETHUNS_OPT_TPACKET_V3           "Enable TPACKET v3 support" OFF)
option(NETHUNS_OPT_XDP                  "Enable XDP" OFF)
option(NETHUNS_OPT_NETMAP               "Enable Netmap support" OFF)

add_definitions(-D_GNU_SOURCE)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(LIBPCAP_LIBRARY NAMES libpcap.a PATHS "/usr/local/opt/libpcap/lib" "/opt/homebrew/opt/libpcap/lib" NO_DEFAULT_PATH)
    find_path(LIBPCAP_INCLUDE_DIR NAMES pcap/pcap.h PATHS "/usr/local/opt/libpcap/include/" "/opt/homebrew/opt/libpcap/include" NO_DEFAULT_PATH)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    find_library(LIBPCAP_LIBRARY NAMES libpcap.a PATHS "/usr/local/lib")
    find_path(LIBPCAP_INCLUDE_DIR NAMES pcap/pcap.h PATHS "/usr/local/include")
else()
    message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} platform not supported!")
endif()

include_directories(${LIBPCAP_INCLUDE_DIR})
include_directories(/usr/local/opt/libpcap/include /usr/local/include/ src)

if (NETHUNS_OPT_XDP)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/)
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
    message("Nethuns: tpacket v3 ENABLED")
    add_definitions(-DNETHUNS_USE_TPACKET_V3)
endif()

if (NETHUNS_OPT_NETMAP)
    list(APPEND NETHUNS_SRC src/nethuns/sockets/netmap.c)
    list(APPEND NETHUNS_DEP -lnetmap)
    list(APPEND OTHER_LIB -lnetmap)

    message("Nethuns: netmap ENABLED")
    add_definitions(-DNETHUNS_USE_NETMAP)
endif()

if (NETHUNS_OPT_XDP)

    message("Nethuns: xdp ENABLED")
    add_definitions(-DNETHUNS_USE_XDP)
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

    message("Nethuns: libpcap ENABLED")
    add_definitions(-DNETHUNS_USE_LIBPCAP)
    list(APPEND NETHUNS_SRC src/nethuns/sockets/libpcap.c)
    list(APPEND NETHUNS_LIBS ${LIBPCAP_LIBRARY})
endif()

add_custom_command(
	OUTPUT  ${CMAKE_CURRENT_SOURCE_DIR}/src/nethuns/version.c
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/nethuns/_version.c # fake target that is never created, here just to trigger the execution of makeRevision script
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/make_revision.sh ${CMAKE_CURRENT_SOURCE_DIR}  ${CMAKE_CURRENT_SOURCE_DIR}/src/nethuns/version.c.in ${CMAKE_CURRENT_SOURCE_DIR}/src/nethuns/version.c ${NETHUNS_OPT_LIBPCAP} ${NETHUNS_OPT_XDP} ${NETHUNS_OPT_NETMAP} ${NETHUNS_OPT_TPACKET_V3}
)


add_custom_target(revision ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/nethuns/version.c)

list(APPEND NETHUNS_SRC src/nethuns/version.c)

add_library(nethuns STATIC ${NETHUNS_SRC})

target_link_libraries(nethuns PRIVATE ${NETHUS_LIBS})

add_dependencies(nethuns revision)

install(TARGETS nethuns DESTINATION /usr/local/lib)

install(DIRECTORY src/nethuns/ 	   	    DESTINATION /usr/local/include/nethuns FILES_MATCHING PATTERN "*.h" PATTERN src/nethuns/sockets/xdp EXCLUDE)
install(DIRECTORY libbpf/src/      	    DESTINATION /usr/local/include/nethuns/sockets/xdp FILES_MATCHING PATTERN "*.h" )
install(DIRECTORY libbpf/include/uapi/  DESTINATION /usr/local/include/nethuns/sockets/xdp FILES_MATCHING PATTERN "*.h" )

if (NETHUNS_OPT_XDP)
    install(FILES     libbpf/src/libbpf.a   DESTINATION /usr/local/lib/)
endif()

#
# build Nethuns.cmake script...

configure_file(scripts/Nethuns.cmake Nethuns.cmake @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/Nethuns.cmake DESTINATION /usr/local/share/nethuns/)
