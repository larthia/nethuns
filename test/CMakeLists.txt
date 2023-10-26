# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.10)

project (nethuns-test)

include(/usr/local/share/nethuns/Nethuns.cmake)

#
# Compiler options...
#

string(FIND "${CMAKE_CXX_COMPILER_ID}" "Clang" CLANG_SUBSTRING_INDEX)
if ("${CLANG_SUBSTRING_INDEX}" GREATER -1)
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -fomit-frame-pointer -Wall -Wextra -Wshadow")
else()
    set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")
endif()


include_directories(${NETHUNS_INCLUDE_DIRS} src)
#link_directories(${NETHUNS_LIBRARY_DIRS} src)

message(STATUS "HDRS: ${NETHUNS_INCLUDE_DIRS}")
message(STATUS "LIBS: ${NETHUNS_LIBRARY_DIRS}")

add_executable(nethuns-version      src/version.c)
add_executable(nethuns-send         src/send.cpp)
add_executable(nethuns-meter        src/meter.cpp)
add_executable(nethuns-filter       src/filter.cpp)
add_executable(nethuns-file-pcap    src/file-pcap.cpp)
add_executable(nethuns-file-pcap-mt src/file-pcap-mt.cpp)
add_executable(nethuns-forward      src/forward.cpp)
add_executable(nethuns-forward-mt   src/forward-mt.cpp)
add_executable(nethuns-meter-mt     src/meter-mt.cpp)

add_executable(pure-pcap-meter      src/pure-meter-pcap.cpp)
add_executable(pure-pcap-meter-mt   src/pure-meter-pcap-mt.cpp)
add_executable(pure-pcap-forward    src/pure-forward-pcap.cpp)
add_executable(pure-pcap-forward-mt src/pure-forward-pcap-mt.cpp)

add_executable(pcap-version         src/pcap-version.c)
target_link_libraries(nethuns-file-pcap-mt  ${NETHUNS_LIBRARY_DIRS} -pthread)

target_link_libraries(nethuns-version       ${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-meter-mt      ${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-send       	${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-forward    	${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-forward-mt 	${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-file-pcap  	${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-meter         ${NETHUNS_LIBRARY_DIRS} -pthread)
target_link_libraries(nethuns-filter        ${NETHUNS_LIBRARY_DIRS} -pthread)

target_link_libraries(pure-pcap-forward      -pthread ${NETHUNS_LIBPCAP_LIBRARY})
target_link_libraries(pure-pcap-forward-mt   -pthread ${NETHUNS_LIBPCAP_LIBRARY})
target_link_libraries(pure-pcap-meter        -pthread ${NETHUNS_LIBPCAP_LIBRARY})
target_link_libraries(pure-pcap-meter-mt     -pthread ${NETHUNS_LIBPCAP_LIBRARY})

target_link_libraries(pcap-version           ${NETHUNS_LIBPCAP_LIBRARY})
