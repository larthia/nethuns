/*
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <nethuns/nethuns.h>
#include <signal.h>

#include "hdr/options.h"
#include "hdr/run.h"

int sig_shutdown;

void sighandler(int sig)
{
    (void)sig;
    __atomic_store_n(&sig_shutdown, 1, __ATOMIC_RELAXED);
}

int
main(int argc, char *argv[])
{
    struct options opt = parse_opt(argc, argv);

    validate_options(&opt);

    signal(SIGINT, sighandler);

    return run(&opt);
}
