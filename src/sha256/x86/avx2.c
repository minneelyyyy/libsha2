/* This is the highest instruction set SHA256 will actually need since there is no
 * benefit to having 512-bit SIMD when the digest is only 256 bits large. */

#include <sha2/sha256.h>
#include <sha2/bits/endian.h>
#include <immintrin.h>

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

void _sha256_hash_block(const SHA256MessageBlock M, SHA256Digest H) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    for (size_t t = 0; t < 16; t++) {
        W[t] = READ_32_BE(&M[t]);
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

static inline __m256i Ch256(__m256i x, __m256i y, __m256i z) {
    // x & y
    __m256i and_result1 = _mm256_and_si256(x, y);

    // ~x & z
    __m256i not_x = _mm256_xor_si256(x, _mm256_set1_epi32(-1));
    __m256i and_result2 = _mm256_and_si256(not_x, z);

    // XOR the results
    __m256i result = _mm256_xor_si256(and_result1, and_result2);

    return result;
}

static inline __m256i Maj256(__m256i x, __m256i y, __m256i z) {
    // x & y
    __m256i and_result1 = _mm256_and_si256(x, y);

    // x & z
    __m256i and_result2 = _mm256_and_si256(x, z);

    // y & z
    __m256i and_result3 = _mm256_and_si256(y, z);

    // XOR the results
    __m256i result = _mm256_xor_si256(_mm256_xor_si256(and_result1, and_result2), and_result3);

    return result;
}

static inline __m256i ROTR256(__m256i x, int n) {
    // Right shift
    __m256i right_shifted = _mm256_srli_epi32(x, n);

    // Left shift
    __m256i left_shifted = _mm256_slli_epi32(x, sizeof(int) * 8 - n);

    // Bitwise OR
    __m256i result = _mm256_or_si256(right_shifted, left_shifted);

    return result;
}

static inline __m256i SHR256(__m256i x, int n) {
    return _mm256_srli_epi32(x, n);
}

static inline __m256i sigma0256(__m256i x) {
    // Perform AVX2 versions of ROTR
    __m256i rotr2 = _mm256_or_si256(_mm256_srli_epi32(x, 2), _mm256_slli_epi32(x, sizeof(int) * 8 - 2));
    __m256i rotr13 = _mm256_or_si256(_mm256_srli_epi32(x, 13), _mm256_slli_epi32(x, sizeof(int) * 8 - 13));
    __m256i rotr22 = _mm256_or_si256(_mm256_srli_epi32(x, 22), _mm256_slli_epi32(x, sizeof(int) * 8 - 22));

    // XOR the results
    __m256i result = _mm256_xor_si256(_mm256_xor_si256(rotr2, rotr13), rotr22);

    return result;
}

static inline __m256i sigma1256(__m256i x) {
    // Perform AVX2 versions of ROTR
    __m256i rotr6 = _mm256_or_si256(_mm256_srli_epi32(x, 6), _mm256_slli_epi32(x, sizeof(int) * 8 - 6));
    __m256i rotr11 = _mm256_or_si256(_mm256_srli_epi32(x, 11), _mm256_slli_epi32(x, sizeof(int) * 8 - 11));
    __m256i rotr25 = _mm256_or_si256(_mm256_srli_epi32(x, 25), _mm256_slli_epi32(x, sizeof(int) * 8 - 25));

    // XOR the results
    __m256i result = _mm256_xor_si256(_mm256_xor_si256(rotr6, rotr11), rotr25);

    return result;
}

static inline __m256i lsigma0256(__m256i x) {
    // Perform AVX2 versions of ROTR and SHR
    __m256i rotr7 = _mm256_or_si256(_mm256_srli_epi32(x, 7), _mm256_slli_epi32(x, sizeof(int) * 8 - 7));
    __m256i rotr18 = _mm256_or_si256(_mm256_srli_epi32(x, 18), _mm256_slli_epi32(x, sizeof(int) * 8 - 18));
    __m256i shr3 = _mm256_srli_epi32(x, 3);

    // XOR the results
    __m256i result = _mm256_xor_si256(_mm256_xor_si256(rotr7, rotr18), shr3);

    return result;
}

static inline __m256i lsigma1256(__m256i x) {
    // Perform AVX2 versions of ROTR and SHR
    __m256i rotr17 = _mm256_or_si256(_mm256_srli_epi32(x, 17), _mm256_slli_epi32(x, sizeof(int) * 8 - 17));
    __m256i rotr19 = _mm256_or_si256(_mm256_srli_epi32(x, 19), _mm256_slli_epi32(x, sizeof(int) * 8 - 19));
    __m256i shr10 = _mm256_srli_epi32(x, 10);

    // XOR the results
    __m256i result = _mm256_xor_si256(_mm256_xor_si256(rotr17, rotr19), shr10);

    return result;
}

#if 0
/* hash 8 blocks and 8 digests concurrently using 256 bit simd registers */
void _sha256_hash_block_x8(const SHA256MessageBlock M[8], SHA256Digest H[8]) {
    __m256i W[64];
    __m256i a, b, c, d, e, f, g, h;
    __m256i T1, T2;

    for (size_t t = 0; t < 16; t++) {
        W[t] = _mm256_set_epi32(
            READ_32_BE(&M[0][t]),
            READ_32_BE(&M[1][t]),
            READ_32_BE(&M[2][t]),
            READ_32_BE(&M[3][t]),
            READ_32_BE(&M[4][t]),
            READ_32_BE(&M[5][t]),
            READ_32_BE(&M[6][t]),
            READ_32_BE(&M[7][t])
        );
    }

    for (size_t t = 16; t < 64; t++) {
        W[t] = _mm256_add_epi32(lsigma1256(W[t - 2]), _mm256_add_epi32(W[t - 7], _mm256_add_epi32(lsigma0256(W[t - 15]), W[t - 16])));
    }

    a = _mm256_set_epi32(H[0][0], H[1][0], H[2][0], H[3][0], H[4][0], H[5][0], H[6][0], H[7][0]);
    b = _mm256_set_epi32(H[0][1], H[1][1], H[2][1], H[3][1], H[4][1], H[5][1], H[6][1], H[7][1]);
    c = _mm256_set_epi32(H[0][2], H[1][2], H[2][2], H[3][2], H[4][2], H[5][2], H[6][2], H[7][2]);
    d = _mm256_set_epi32(H[0][3], H[1][3], H[2][3], H[3][3], H[4][3], H[5][3], H[6][3], H[7][3]);
    e = _mm256_set_epi32(H[0][4], H[1][4], H[2][4], H[3][4], H[4][4], H[5][4], H[6][4], H[7][4]);
    f = _mm256_set_epi32(H[0][5], H[1][5], H[2][5], H[3][5], H[4][5], H[5][5], H[6][5], H[7][5]);
    g = _mm256_set_epi32(H[0][6], H[1][6], H[2][6], H[3][6], H[4][6], H[5][6], H[6][6], H[7][6]);
    h = _mm256_set_epi32(H[0][7], H[1][7], H[2][7], H[3][7], H[4][7], H[5][7], H[6][7], H[7][7]);

    for (size_t t = 0; t < 64; t++) {
        T1 = _mm256_add_epi32(h, _mm256_add_epi32(sigma1256(e), _mm256_add_epi32(Ch256(e, f, g), _mm256_add_epi32(_mm256_set1_epi32(K[t]), W[t]))));
        T2 = _mm256_add_epi32(sigma0256(a), Maj256(a, b, c));
        h = g;
        g = f;
        f = e;
        e = _mm256_add_epi32(d, T1);
        d = c;
        c = b;
        b = a;
        a = _mm256_add_epi32(T1, T2);
    }

    H[0][0] = _mm256_extract_epi32(a, 0);
    H[1][0] = _mm256_extract_epi32(a, 1);
    H[2][0] = _mm256_extract_epi32(a, 2);
    H[3][0] = _mm256_extract_epi32(a, 3);
    H[4][0] = _mm256_extract_epi32(a, 4);
    H[5][0] = _mm256_extract_epi32(a, 5);
    H[6][0] = _mm256_extract_epi32(a, 6);
    H[7][0] = _mm256_extract_epi32(a, 7);

    H[0][1] = _mm256_extract_epi32(b, 0);
    H[1][1] = _mm256_extract_epi32(b, 1);
    H[2][1] = _mm256_extract_epi32(b, 2);
    H[3][1] = _mm256_extract_epi32(b, 3);
    H[4][1] = _mm256_extract_epi32(b, 4);
    H[5][1] = _mm256_extract_epi32(b, 5);
    H[6][1] = _mm256_extract_epi32(b, 6);
    H[7][1] = _mm256_extract_epi32(b, 7);

    H[0][2] = _mm256_extract_epi32(c, 0);
    H[1][2] = _mm256_extract_epi32(c, 1);
    H[2][2] = _mm256_extract_epi32(c, 2);
    H[3][2] = _mm256_extract_epi32(c, 3);
    H[4][2] = _mm256_extract_epi32(c, 4);
    H[5][2] = _mm256_extract_epi32(c, 5);
    H[6][2] = _mm256_extract_epi32(c, 6);
    H[7][2] = _mm256_extract_epi32(c, 7);

    H[0][3] = _mm256_extract_epi32(d, 0);
    H[1][3] = _mm256_extract_epi32(d, 1);
    H[2][3] = _mm256_extract_epi32(d, 2);
    H[3][3] = _mm256_extract_epi32(d, 3);
    H[4][3] = _mm256_extract_epi32(d, 4);
    H[5][3] = _mm256_extract_epi32(d, 5);
    H[6][3] = _mm256_extract_epi32(d, 6);
    H[7][3] = _mm256_extract_epi32(d, 7);

    H[0][4] = _mm256_extract_epi32(e, 0);
    H[1][4] = _mm256_extract_epi32(e, 1);
    H[2][4] = _mm256_extract_epi32(e, 2);
    H[3][4] = _mm256_extract_epi32(e, 3);
    H[4][4] = _mm256_extract_epi32(e, 4);
    H[5][4] = _mm256_extract_epi32(e, 5);
    H[6][4] = _mm256_extract_epi32(e, 6);
    H[7][4] = _mm256_extract_epi32(e, 7);

    H[0][5] = _mm256_extract_epi32(f, 0);
    H[1][5] = _mm256_extract_epi32(f, 1);
    H[2][5] = _mm256_extract_epi32(f, 2);
    H[3][5] = _mm256_extract_epi32(f, 3);
    H[4][5] = _mm256_extract_epi32(f, 4);
    H[5][5] = _mm256_extract_epi32(f, 5);
    H[6][5] = _mm256_extract_epi32(f, 6);
    H[7][5] = _mm256_extract_epi32(f, 7);

    H[0][6] = _mm256_extract_epi32(g, 0);
    H[1][6] = _mm256_extract_epi32(g, 1);
    H[2][6] = _mm256_extract_epi32(g, 2);
    H[3][6] = _mm256_extract_epi32(g, 3);
    H[4][6] = _mm256_extract_epi32(g, 4);
    H[5][6] = _mm256_extract_epi32(g, 5);
    H[6][6] = _mm256_extract_epi32(g, 6);
    H[7][6] = _mm256_extract_epi32(g, 7);

    H[0][7] = _mm256_extract_epi32(h, 0);
    H[1][7] = _mm256_extract_epi32(h, 1);
    H[2][7] = _mm256_extract_epi32(h, 2);
    H[3][7] = _mm256_extract_epi32(h, 3);
    H[4][7] = _mm256_extract_epi32(h, 4);
    H[5][7] = _mm256_extract_epi32(h, 5);
    H[6][7] = _mm256_extract_epi32(h, 6);
    H[7][7] = _mm256_extract_epi32(h, 7);
}
#else
void _sha256_hash_block_x8(const SHA256MessageBlock M[8], SHA256Digest H[8]) {
    for (size_t i = 0; i < 8; i++) {
        _sha256_hash_block(M[i], H[i]);
    }
}
#endif

void _sha256(const SHA256MessageBlock *M, size_t N, SHA256Digest H) {
    for (size_t i = 0; i < N; i++) {
        _sha256_hash_block(M[i], H);
    }
}
