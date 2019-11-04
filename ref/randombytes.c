/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <fcntl.h>
#include <unistd.h>

#include "randombytes.h"

static int fd = -1;

void randombytes(unsigned char *x, size_t xlen)
{
    ssize_t i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = (ssize_t)xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, (size_t)i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= (size_t)i;
    }
}
