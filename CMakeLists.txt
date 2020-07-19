cmake_minimum_required(VERSION 2.8)

project (nethuns)

include (Nethuns.cmake)

#
# Compiler options...
#

# set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -fsanitize=address -fsanitize=undefined")   
# set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -fsanitize=address -fsanitize=undefined")

set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")   
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -std=c++17 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow")


set (CMAKE_POSITION_INDEPENDENT_CODE ON)

add_definitions(-D_GNU_SOURCE)
include_directories(/usr/local/include/ src) 
if (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp")
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/)
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
endif() 
option(NETHUNS_BUILD_TESTS "Build regression tests" OFF)

#
# define the list of library to link...
#

set(NETHUNS_DEP)

set(NETHUNS_SRC src/nethuns/nethuns.c 
		src/nethuns/global.c
                src/nethuns/sockets/pcap_reader.c)

if (NETHUNS_BUILTIN_PCAP_READER)
    message("Nethuns: using built-in pcap file reader!")
else()
    list(APPEND NETHUNS_DEP -lpcap)

    list(APPEND OTHER_LIB -lpcap)
    message("Nethuns: using libpcap to read files!")
endif()

list(APPEND OTHER_LIB -pthread)

if (NETHUNS_CAPTURE_SOCKET STREQUAL "tpacket3")

    list(APPEND NETHUNS_SRC src/nethuns/sockets/tpacket_v3.c)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "netmap")

    list(APPEND NETHUNS_SRC src/nethuns/sockets/netmap.c)
    
elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "xdp")
    
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
    list(APPEND NETHUNS_SRC src/nethuns/sockets/xdp/xsk_ext.c)

    list(APPEND NETHUNS_DEP libbpf)
    list(APPEND NETHUNS_DEP -lelf)
    list(APPEND NETHUNS_DEP ZLIB::ZLIB)

elseif (NETHUNS_CAPTURE_SOCKET STREQUAL "libpcap")

    list(APPEND NETHUNS_SRC src/nethuns/sockets/libpcap.c)
    list(APPEND NETHUNS_DEP -lpcap)
    list(APPEND OTHER_LIB -lpcap)

endif()


add_library(nethuns STATIC ${NETHUNS_SRC})

target_link_libraries(nethuns ${NETHUNS_DEP})

link_directories(${nethuns_BINARY_DIR})

#
# Build tests..
#

if (NETHUNS_BUILD_TESTS)

    add_executable(nethuns-test         test/test.c)
    add_executable(nethuns-send         test/send.cpp)
    add_executable(nethuns-meter        test/meter.cpp)
    add_executable(nethuns-filter       test/filter.cpp)
    add_executable(nethuns-file-pcap    test/file-pcap.cpp)
    add_executable(nethuns-file-pcap-mt test/file-pcap-mt.cpp)
    add_executable(nethuns-forward      test/forward.cpp)
    add_executable(nethuns-forward-mt   test/forward-mt.cpp)
    add_executable(nethuns-meter-mt     test/meter-mt.cpp)

    add_executable(pcap-meter         test/meter-pcap.cpp)
    add_executable(pcap-forward       test/forward-pcap.cpp)
    add_executable(pcap-forward-mt    test/forward-pcap-mt.cpp)
    add_executable(pcap-meter-mt      test/meter-pcap-mt.cpp)


    target_link_libraries(nethuns-test       	${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-send       	${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-forward    	${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-forward-mt 	${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-file-pcap  	${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-file-pcap-mt  ${OTHER_LIB} nethuns -pthread)

    target_link_libraries(nethuns-meter      ${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-meter-mt   ${OTHER_LIB} nethuns)
    target_link_libraries(nethuns-filter     ${OTHER_LIB} nethuns)

    target_link_libraries(pcap-forward      -lpcap  -pthread)
    target_link_libraries(pcap-forward-mt   -lpcap  -pthread)
    target_link_libraries(pcap-meter        -lpcap  -pthread)
    target_link_libraries(pcap-meter-mt     -lpcap  -pthread)

endif()

install_targets(/lib nethuns)

install(DIRECTORY src/nethuns/ DESTINATION /usr/local/include/nethuns FILES_MATCHING PATTERN "*.h")

