#pragma once
#include <nethuns/nethuns.h>

void dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame, bool verbose);
