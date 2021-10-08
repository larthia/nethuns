#pragma once
#include <nethuns/nethuns.h>

void dump_frame(nethuns_pkthdr_t const *hdr, const unsigned char *frame, const char *dev, int queue, bool verbose);
