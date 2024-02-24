#ifdef NETHUNS_HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif

const char *
nethuns_version_full()
{
#ifdef NETHUNS_HAVE_LIBPCAP
    char *ret;
    if (asprintf(&ret, "nethuns v3.1.0; %s; libpcap:ON xdp:OFF netmap:OFF tpacket3:OFF", pcap_lib_version()) < 0) {
    	return "nethuns v3.1.0; libpcap:ON xdp:OFF netmap:OFF tpacket3:OFF";
    }
    return ret;
#else
    return "nethuns v3.1.0; libpcap:ON xdp:OFF netmap:OFF tpacket3:OFF";
#endif
}

const char *
nethuns_version()
{
    return "nethuns v3.1.0";
}
