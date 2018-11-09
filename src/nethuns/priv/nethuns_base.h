#pragma once

    void nethuns_perror(char *buf, char *format, ...);

#define nethuns_error(sock) (sock->base.errbuf)
