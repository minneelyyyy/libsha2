#include <sha2/sha256.h>
#include <sha2/bits/endian.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define DIFFICULTY 3
#define CHALLENGE "hello!"

bool check_difficulty(SHA256Digest hash, size_t difficulty) {
        for (size_t i = 0; i < difficulty; i++) {
                if (((char*)hash)[i]) return false;
        }

        return true;
}

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

int main(void) {
    size_t u = 0;

    printf("Difficulty: %u\n", DIFFICULTY);
    printf("Challenge: \"%s\"\n", CHALLENGE);

    for (;;) {
        SHA256MessageBlock blocks[8] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
        SHA256Digest digests[8];
        int sz[8];

        init_digest(digests[0]);
        init_digest(digests[1]);
        init_digest(digests[2]);
        init_digest(digests[3]);
        init_digest(digests[4]);
        init_digest(digests[5]);
        init_digest(digests[6]);
        init_digest(digests[7]);

        for (size_t i = 0; i < 8; i++) {
            sz[i] = snprintf((char*)blocks[i], sizeof(blocks[0]), CHALLENGE "%lu", u + i);
            sha256_pad_message(&blocks[i], 1, sz[i] * 8, sz[0] * 8);
        }

        _sha256_hash_block_x8(blocks, digests);

        for (size_t j = 0; j < 8; j++) {
            for (size_t i = 0; i < 8; i++) {
                digests[j][i] = READ_32_BE(&digests[j][i]);
            }
        }

        for (size_t i = 0; i < 8; i++) {
            if (check_difficulty(digests[i], DIFFICULTY)) {
                char hashstr[64];

                printf("string found: %*.*s\n", sz[i], sz[i], (char*)blocks[i]);
                printf("hash: %64.64s\n", sha256tos(hashstr, digests[i]));
                return 0;
            }
        }

        u += 8;
    }

    return 0;
}