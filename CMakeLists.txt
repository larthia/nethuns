cmake_minimum_required(VERSION 2.4)

project (nethuns)

#set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion -fsanitize=address -fsanitize=undefined")
set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion ")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion ")


include_directories(src)

add_definitions(-D_GNU_SOURCE)

add_library(nethuns_static STATIC src/nethuns.c)
add_library(nethuns SHARED src/nethuns.c)


link_directories(${nethuns_BINARY_DIR})

add_executable(nethuns-meter   test/meter.cpp)
add_executable(pcap-meter      test/meter-pcap.cpp)

add_executable(nethuns-test    test/test.c)
add_executable(nethuns-forward test/forward.cpp)
add_executable(nethuns-send    test/send.cpp)


target_link_libraries(nethuns-test    nethuns)
target_link_libraries(nethuns-send    nethuns -pthread)
target_link_libraries(nethuns-forward nethuns -pthread)

target_link_libraries(nethuns-meter   nethuns -pthread)
target_link_libraries(pcap-meter      -lpcap  -pthread)

install_targets(/lib nethuns)
install_targets(/lib nethuns_static)

install_files(/include/nethuns FILES src/nethuns.h)
