/*
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <nethuns/nethuns.h>
#include <stdio.h>
#include <signal.h>

#include "nethuns/define.h"
#include "nethuns/types.h"

#include "hdr/options.h"
#include "hdr/dump.h"
#include "hdr/run.h"

void sighandler(int sig)
{
    exit(0);
}

int
main(int argc, char *argv[])
{
    struct options opt = parse_opt(argc, argv);

    validate_options(&opt);

    signal(SIGINT, sighandler);

    return run(&opt);
}