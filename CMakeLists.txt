cmake_minimum_required(VERSION 2.8)

project (nethuns)

#
# Compiler options...
#

set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow ")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow ")

add_definitions(-D_GNU_SOURCE)
include_directories(/usr/local/include/ src)

#
# Nethuns options...
#

set(NETHUNS_CAPTURE_SOCKET "tpacket3" CACHE STRING "Nethuns underlying capture engine")
set_property(CACHE NETHUNS_CAPTURE_SOCKET PROPERTY STRINGS tpacket3 libpcap)
option(NETHUNS_BUILD_TESTS "Build regression tests" OFF)

#
# define the list of library to link...
#

set(NETHUNS_SRC src/nethuns/nethuns.c 
                src/nethuns/internals/filepcap.c)

set(NETHUNS_LIB nethuns)
set(NETHUNS_DEP)


list(APPEND NETHUNS_LIB -pthread)


if (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")

    message ("Native TPACKET_v3 enabled!")

    add_definitions(-DNETHUNS_USE_TPACKET_V3)
    list(APPEND NETHUNS_SRC src/nethuns/internals/tpacket_v3.c)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")

    message ("Basic libpcap enabled!")

    add_definitions(-DNETHUNS_USE_DEVPCAP)
    list(APPEND NETHUNS_SRC src/nethuns/internals/devpcap.c)
    list(APPEND NETHUNS_DEP -lpcap)
    list(APPEND NETHUNS_LIB -lpcap)

endif()

#
# Build the Nethuns library
#

add_library(nethuns_static STATIC ${NETHUNS_SRC})
add_library(nethuns SHARED ${NETHUNS_SRC})

target_link_libraries(nethuns ${NETHUNS_DEP})
target_link_libraries(nethuns_static ${NETHUNS_DEP})


link_directories(${nethuns_BINARY_DIR})

#
# Build tests..
#

if (NETHUNS_BUILD_TESTS)

    add_executable(nethuns-test       test/test.c)
    add_executable(nethuns-send       test/send.cpp)
    add_executable(nethuns-meter      test/meter.cpp)
    add_executable(nethuns-file-pcap  test/file-pcap.cpp)
    add_executable(nethuns-forward    test/forward.cpp)
    add_executable(nethuns-forward-mt test/forward-mt.cpp)
    add_executable(nethuns-meter-mt   test/meter-mt.cpp)

    add_executable(pcap-meter         test/meter-pcap.cpp)
    add_executable(pcap-forward       test/forward-pcap.cpp)
    add_executable(pcap-forward-mt    test/forward-pcap-mt.cpp)
    add_executable(pcap-meter-mt      test/meter-pcap-mt.cpp)


    target_link_libraries(nethuns-test       ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-send       ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-forward    ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-forward-mt ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-file-pcap  ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-meter      ${NETHUNS_LIB} -lnethuns)
    target_link_libraries(nethuns-meter-mt   ${NETHUNS_LIB} -lnethuns)


    target_link_libraries(pcap-forward      -lpcap  -pthread)
    target_link_libraries(pcap-forward-mt   -lpcap  -pthread)
    target_link_libraries(pcap-meter        -lpcap  -pthread)
    target_link_libraries(pcap-meter-mt     -lpcap  -pthread)

endif()

install_targets(/lib nethuns)
install_targets(/lib nethuns_static)

install_files(/include/nethuns FILES src/nethuns.h)
