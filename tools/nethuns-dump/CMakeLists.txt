# Copyright 2021 Larthia, University of Pisa. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

cmake_minimum_required(VERSION 3.10)

project (nethuns-dump)

include(/usr/local/share/nethuns/Nethuns.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# Compiler options...
#

include_directories(${NETHUNS_INCLUDE_DIRS} . ../src)

link_directories(/usr/local/lib)

add_executable(nethuns-dump src/main.c
                            src/options.c
                            src/dump.c
                            src/run.c)

target_link_libraries(nethuns-dump ${NETHUNS_LIBRARY_DIRS} -pthread)
