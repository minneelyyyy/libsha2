#include <sha2/sha256.h>
#include <sha2/bits/endian.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#define DIFFICULTY 3
#define CHALLENGE "hello!"

/* should be tuned to roughly where the algorithm takes a second or so.
 * ideally also is a multiple of 8 to make maximum use of simd. */
#define RANGE (10000 * 8)
#define THREAD_COUNT (8)

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

struct hashing_results {
    SHA256Digest winner;
    char format[64];
};

struct range_args {
    size_t low, high;
};

#define MIN(__x, __y) ((__x) < (__y) ? (__x) : (__y))

struct hashing_results *run_range(struct range_args *args) {
    /* IDK if this is strictly necessary but local variables
     * would be speedier than the heap allocated args struct.
     * copy the values over once into locals. */
    size_t u = args->low;
    size_t max = args->high;

    while (u < max) {
        SHA256MessageBlock blocks[8] = {{0}};
        SHA256Digest digests[8];
        size_t sz[8];

        /* We don't want to go over the max, so select a minimum between
         * 8 and the difference between our current u and the max */
        size_t count = MIN(args->high - u, 8);

        for (size_t i = 0; i < count; i++) {
            init_digest(digests[i]);
        }

        for (size_t i = 0; i < count; i++) {
            sz[i] = snprintf((char*)blocks[i], sizeof(blocks[0]), CHALLENGE "%lu", u + i);
            sha256_pad_message(&blocks[i], 1, sz[i] * 8, sz[i] * 8);
        }

        _sha256_hash_block_x8(blocks, digests);

        for (size_t i = 0; i < count; i++) {
            for (size_t j = 0; j < 8; j++) {
                digests[i][j] = READ_32_BE(&digests[i][j]);
            }
        }

        for (size_t i = 0; i < count; i++) {
            if (check_difficulty(digests[i], DIFFICULTY)) {
                struct hashing_results *ret = malloc(sizeof(struct hashing_results));

                memcpy(ret->winner, digests[i], sizeof(SHA256Digest));
                strncpy(ret->format, (char*)blocks[i], MIN(sz[i], sizeof(ret->format)));
                ret->format[sizeof(ret->format) - 1] = '\0';

                return ret;
            }
        }

        u += 8;
    }

    return NULL;
}

int main(void) {
    printf("Difficulty: %u\n", DIFFICULTY);
    printf("Challenge: \"%s\"\n", CHALLENGE);

    size_t s = 0;
    struct range_args args[THREAD_COUNT];

    pthread_t threads[THREAD_COUNT];

    for (size_t i = 0; i < THREAD_COUNT; i++) {
        args[i].low = s;
        args[i].high = s += RANGE;

        pthread_create(&threads[i], NULL, run_range, &args[i]);
    }

    for (size_t i = 0; i < THREAD_COUNT; i = (i + 1) % THREAD_COUNT) {
        struct hashing_results *ret;

        pthread_join(threads[i], &ret);

        if (ret != NULL) {
            char hash[64];

            printf("string found: %s\n", ret->format);
            printf("hash: %64.64s\n", sha256tos(hash, ret->winner));

            return 0;
        } else {
            args[i].low = s;
            args[i].high = s += RANGE;

            pthread_create(&threads[i], NULL, run_range, &args[i]);
        }
    }

    return 0;
}