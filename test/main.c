#include <nethuns.h>

int
main(int argc, char *argv[])
{
    struct nethuns_socket * s = nethuns_open(1,2,3);


    nethuns_close(s);
     return 0;
}

