cmake_minimum_required(VERSION 2.4)

project (nethuns)

add_definitions(-DNETHUNS_USE_TPACKET_V3)


#set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O2 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion -fsanitize=address -fsanitize=undefined")
set (CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion ")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -march=native -fomit-frame-pointer -Wall -Wextra -Wshadow -Wconversion ")


include_directories(src)


add_definitions(-D_GNU_SOURCE)

set(NETHUNS_SRC src/internals/tpacket_v3.c
                src/internals/pcap.c 
   )


add_library(nethuns_static STATIC ${NETHUNS_SRC})
add_library(nethuns SHARED ${NETHUNS_SRC})


link_directories(${nethuns_BINARY_DIR})


add_executable(nethuns-test       test/test.c)
add_executable(nethuns-send       test/send.cpp)
add_executable(nethuns-meter      test/meter.cpp)
add_executable(pcap-meter         test/meter-pcap.cpp)
add_executable(nethuns-forward    test/forward.cpp)
add_executable(nethuns-forward-mt test/forward-mt.cpp)
add_executable(pcap-forward       test/forward-pcap.cpp)
add_executable(pcap-forward-mt    test/forward-pcap-mt.cpp)
add_executable(nethuns-meter-mt   test/meter-mt.cpp)
add_executable(pcap-meter-mt      test/meter-pcap-mt.cpp)
add_executable(file-pcap          test/file-pcap.cpp)


target_link_libraries(nethuns-test       nethuns)
target_link_libraries(nethuns-send       nethuns -pthread)
target_link_libraries(nethuns-forward    nethuns -pthread)
target_link_libraries(nethuns-forward-mt nethuns -pthread)
target_link_libraries(file-pcap          nethuns)

target_link_libraries(pcap-forward      -lpcap  -pthread)
target_link_libraries(pcap-forward-mt   -lpcap  -pthread)
target_link_libraries(nethuns-meter     nethuns -pthread)
target_link_libraries(nethuns-meter-mt  nethuns -pthread)
target_link_libraries(pcap-meter        -lpcap  -pthread)
target_link_libraries(pcap-meter-mt     -lpcap  -pthread)


install_targets(/lib nethuns)
install_targets(/lib nethuns_static)

install_files(/include/nethuns FILES src/nethuns.h)
