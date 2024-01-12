/* This is the highest instruction set SHA256 will actually need since there is no
 * benefit to having 512-bit SIMD when the digest is only 256 bits large. */

#include <sha2/sha256.h>