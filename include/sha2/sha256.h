#ifndef __SHA256_H
#define __SHA256_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <sha2/bits/endian.h>

typedef uint32_t SHA256Digest[8];
typedef uint32_t SHA256MessageBlock[16];

/** Perform the full SHA256 algorithm, including preprocessing. The resulting digest is "final" and shouldn't be mutated again.
 * This is best used for a small M that you can fit entirely into memory, this cannot be streamed.
 * @param M Message to hash.
 * @param nbytes Size of M in bytes.
 * @param H Digest to write to.
 */
void sha256(const void *M, size_t nbytes, SHA256Digest H);

/** Writes a SHA256 digest into a buffer as ascii letters.
 * @param out Buffer to write to.
 * @param digest Digest to write.
 * @return The buffer passed to it.
*/
char *sha256tos(char out[64], SHA256Digest digest);

#define sizeof_bits(__expr) (sizeof(__expr) * 8)

void sha256_pad_message(SHA256MessageBlock* blocks, size_t block_cnt, uint64_t l_to_write, uint64_t l);

SHA256MessageBlock *sha256_padded_message(const void *M, size_t nbytes, uint64_t l_to_write, size_t *N);

void _sha256_hash_block_x8(const SHA256MessageBlock M[8], SHA256Digest H[8]);

#endif /* __SHA256_H */