# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.10)

project (nethuns-gen)

include(/usr/local/share/nethuns/Nethuns.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing -fomit-frame-pointer -fno-stack-protector -Wall -Wextra -Wno-unused-local-typedef -std=c++20 -pipe")

#
# Compiler options...
#

include_directories(${NETHUNS_INCLUDE_DIRS} . ../src)

link_directories(/usr/local/lib)

add_executable(nethuns-gen  src/main.cpp
                            src/options.cpp
                            src/generator.cpp
                            src/packets.cpp)

target_link_libraries(nethuns-gen ${NETHUNS_LIBRARY_DIRS} -pthread)
