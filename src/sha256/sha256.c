#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sha2/sha256.h>
#include <sha2/bits/endian.h>

/* Implements the actual sha256 algorithm. A basic implementation can be found in src/sha256/generic.c */
extern void _sha256(const SHA256MessageBlock *M, size_t N, SHA256Digest H);

#define elems(__vec) (sizeof(__vec) / sizeof(__vec[0]))
#define sizeof_bits(__expr) (sizeof(__expr) * 8)

static inline void init_digest(SHA256Digest H) {
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
}

static size_t get_block_cnt(uint64_t l) {
    size_t padding_bits = (448 - (l + 1)) % sizeof_bits(SHA256MessageBlock);
    size_t total_bits = l + 1 + padding_bits + sizeof_bits(l);

    return total_bits / sizeof_bits(SHA256MessageBlock);
}

static void pad_message(SHA256MessageBlock* blocks, size_t block_cnt, uint64_t l_to_write, uint64_t l) {
    ((char*)blocks)[l / 8] |= 0x80;
    WRITE_64_BE(l_to_write, &((uint64_t*)blocks)[block_cnt * sizeof(SHA256MessageBlock) / sizeof(uint64_t) - 1]);
}

static SHA256MessageBlock *padded_message(const void *M, size_t nbytes, uint64_t l_to_write, size_t *N) {
    uint64_t l = nbytes * 8;
    size_t block_cnt = get_block_cnt(l);

    SHA256MessageBlock *blocks = calloc(block_cnt, sizeof(SHA256MessageBlock));
    memcpy(blocks, M, nbytes);

    pad_message(blocks, block_cnt, l_to_write, l);

    if (N != NULL)
        *N = block_cnt;

    return blocks;
}

/* Performs the steps defined in FIPS 180-2 section 6.2.1 SHA-256 Preprocessing, then calls _sha256. */
void sha256(const void *M, size_t nbytes, SHA256Digest H) {
    size_t N;

    SHA256MessageBlock *blocks = padded_message(M, nbytes, nbytes * 8, &N);
    init_digest(H);

    _sha256(blocks, N, H);

    free(blocks);

    /* this entire time we have probably been working with little endian numbers on most cpus.
     * this goes through each word in the final digest and flips the bytes. */
    for (size_t i = 0; i < 8; i++) {
        H[i] = READ_32_BE(&H[i]);
    }
}

static char tohex[] = {
    '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f',
};

char *sha256tos(char out[64], SHA256Digest digest) {
    uint16_t *wout = (uint16_t*)out;

    for (size_t i = 0; i < sizeof(SHA256Digest); i++) {
        unsigned char c = ((char*)digest)[i];
        wout[i] = tohex[(c & 0xF0) >> 4] | tohex[c & 0x0F] << 8;
    }

    return out;
}

#define SHA_ALGORITHM SHA256
#define MESSAGE_BLOCK_T SHA256MessageBlock
#define DIGEST_T SHA256Digest
#define l_T uint64_t
#define SHA_F _sha256
#define STREAM_F sha256_stream
#define STREAM_INIT_F sha256_stream_init
#define STREAM_INIT_NO_DEFAULTS_F sha256_stream_init_no_defaults
#define STREAM_FINISH_F sha256_stream_finish

#include "../streaming.c"
