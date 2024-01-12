/* A generic implementation that will work on any CPU with any instruction set. */

#include <sha2/sha256.h>
#include <sha2/bits/endian.h>

#define sizeof_bits(__expr) (sizeof(__expr) * 8)

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | x << (sizeof_bits(uint32_t) - n);
}

static inline uint32_t SHR(uint32_t x, uint32_t n) {
    return x >> n;
}

static inline uint32_t sigma0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static inline uint32_t sigma1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static inline uint32_t lsigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

static inline uint32_t lsigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

/* The rest of the SHA-256 algorithm (6.2.2 Hash Computation) */
void _sha256(const SHA256MessageBlock *M, size_t N, SHA256Digest H) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    for (size_t i = 1; i <= N; i++) {
        for (size_t t = 0; t < 16; t++) {
            W[t] = READ_32_BE(&M[i - 1][t]);
        }

        for (size_t t = 16; t < 64; t++) {
            W[t] = lsigma1(W[t - 2]) + W[t - 7] + lsigma0(W[t - 15]) + W[t - 16];
        }

        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        for (size_t t = 0; t < 64; t++) {
            T1 = h + sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            T2 = sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
}