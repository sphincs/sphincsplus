/*
 * This is the Windows-specific implementation of randombytes, using BCryptGenRandom.
 */

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h> /* For fprintf, stderr */
#include <stdlib.h> /* For exit */
#include "randombytes.h"

//#pragma comment(lib, "bcrypt.lib")

void randombytes(unsigned char *x, unsigned long long xlen)
{
    NTSTATUS status = BCryptGenRandom(NULL, x, (ULONG)xlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) { /* STATUS_SUCCESS is 0 */
        fprintf(stderr, "Fatal error: BCryptGenRandom failed.\n");
        exit(1);
    }
}
