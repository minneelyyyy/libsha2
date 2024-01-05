#ifndef __SHA256_H
#define __SHA256_H

#include <stddef.h>
#include <inttypes.h>

typedef uint32_t SHA256Digest[8];

void sha256(const void *M, size_t nbytes, SHA256Digest H);

#endif /* __SHA256_H */