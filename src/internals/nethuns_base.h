#pragma once

    void nethuns_perror(char *buf, char *msg);

#define nethuns_error(sock) (sock->base.errbuf)