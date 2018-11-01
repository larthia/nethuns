#pragma once

#include "../types.h"

struct nethuns_ring_slot
{
    bool                    inuse;
#ifdef NETHUNS_USE_TPACKET_V3
    struct tpacket3_hdr     pkthdr;
#endif
    unsigned char           packet[];
};

