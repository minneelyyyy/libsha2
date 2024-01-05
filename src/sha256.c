#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sha256.h>

#define WRITE_32_BE(__v, __b)                                      \
    do {                                                           \
        ((unsigned char*)__b)[3] = (((uint32_t)__v) >> 0 ) & 0xff; \
        ((unsigned char*)__b)[2] = (((uint32_t)__v) >> 8 ) & 0xff; \
        ((unsigned char*)__b)[1] = (((uint32_t)__v) >> 16) & 0xff; \
        ((unsigned char*)__b)[0] = (((uint32_t)__v) >> 24) & 0xff; \
    } while(0)

#define READ_32_BE(__b) (((uint32_t)((unsigned char*)__b)[3]) |       \
                         ((uint32_t)((unsigned char*)__b)[2] << 8) |  \
						 ((uint32_t)((unsigned char*)__b)[1] << 16) | \
						 ((uint32_t)((unsigned char*)__b)[0] << 24))

#define WRITE_64_BE(__v, __b)                                      \
    do {                                                           \
	    ((unsigned char*)__b)[7] = (((uint64_t)__v) >> 0 ) & 0xff; \
        ((unsigned char*)__b)[6] = (((uint64_t)__v) >> 8 ) & 0xff; \
        ((unsigned char*)__b)[5] = (((uint64_t)__v) >> 16) & 0xff; \
        ((unsigned char*)__b)[4] = (((uint64_t)__v) >> 24) & 0xff; \
        ((unsigned char*)__b)[3] = (((uint64_t)__v) >> 32) & 0xff; \
        ((unsigned char*)__b)[2] = (((uint64_t)__v) >> 40) & 0xff; \
        ((unsigned char*)__b)[1] = (((uint64_t)__v) >> 48) & 0xff; \
        ((unsigned char*)__b)[0] = (((uint64_t)__v) >> 56) & 0xff; \
    } while(0)

#define READ_64_BE(__b) (((uint64_t)((unsigned char*)__b)[7]) |         \
                         (((uint64_t)((unsigned char*)__b)[6]) << 8) |  \
                         (((uint64_t)((unsigned char*)__b)[5]) << 16) | \
                         (((uint64_t)((unsigned char*)__b)[4]) << 24) | \
                         (((uint64_t)((unsigned char*)__b)[3]) << 32) | \
                         (((uint64_t)((unsigned char*)__b)[2]) << 40) | \
                         (((uint64_t)((unsigned char*)__b)[1]) << 48) | \
                         (((uint64_t)((unsigned char*)__b)[0]) << 56))

#define elems(__vec) (sizeof(__vec) / sizeof(__vec[0]))
#define sizeof_bits(__expr) (sizeof(__expr) * 8)

typedef uint32_t MessageBlock[16];

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
static void _sha256(const MessageBlock *M, size_t N, SHA256Digest H) {
	uint32_t W[64];

	for (size_t i = 1; i <= N; i++) {
		for (size_t t = 0; t < 16; t++) {
			W[t] = READ_32_BE(&M[i - 1][t]);
		}

		for (size_t t = 16; t < 64; t++) {
			W[t] = lsigma1(W[t-2]) + W[t-7] + lsigma0(W[t-15]) + W[t-16];
		}

		uint32_t a = H[0];
		uint32_t b = H[1];
		uint32_t c = H[2];
		uint32_t d = H[3];
		uint32_t e = H[4];
		uint32_t f = H[5];
		uint32_t g = H[6];
		uint32_t h = H[7];

		for (size_t t = 0; t < 64; t++) {
			uint32_t T1 = h + sigma1(e) + Ch(e, f, g) + K[t] + W[t];
			uint32_t T2 = sigma0(a) + Maj(a, b, c);
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

/* Performs the steps defined in FIPS 180-2 section 6.2.1 SHA-256 Preprocessing, then calls _sha256. */
void sha256(const void *M, size_t nbytes, SHA256Digest H) {
	uint64_t l = nbytes * 8;
	size_t padding_bits = 448 - (l + 1);
	size_t total_bits = l + 1 + padding_bits + sizeof_bits(l);
	size_t N = total_bits / sizeof_bits(MessageBlock);

	assert(total_bits % 512 == 0);

	MessageBlock* blocks = calloc(N, sizeof(MessageBlock));

	/* the padded M is defined to be M + literal 1 bit + padding_bits 0s + l as u64be */
	memcpy(blocks, M, nbytes);

	/* literal 1 right after the initial M */
	((char*)blocks)[nbytes] |= 0x80;

	/* the spec specifies that l gets written as a little endian number.
	 * this math is ugly. All it does is get the last u64 of the block. */
	WRITE_64_BE(l, &((uint64_t*)blocks)[N * sizeof(MessageBlock) / sizeof(uint64_t) - 1]);

	H[0] = 0x6a09e667;
	H[1] = 0xbb67ae85;
	H[2] = 0x3c6ef372;
	H[3] = 0xa54ff53a;
	H[4] = 0x510e527f;
	H[5] = 0x9b05688c;
	H[6] = 0x1f83d9ab;
	H[7] = 0x5be0cd19;

	_sha256(blocks, N, H);

	free(blocks);

	/* this entire time we have probably been working with little endian numbers on most cpus.
	 * this goes through each word in the final digest and flips the bytes. */
	for (size_t i = 0; i < 8; i++) {
		H[i] = READ_32_BE(&H[i]);
	}
}
