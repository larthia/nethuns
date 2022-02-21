/**
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <pcap/pcap.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
    printf("version: %s\n", pcap_lib_version());
}
