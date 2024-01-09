#ifndef __SHA256_H
#define __SHA256_H

#include <stddef.h>
#include <inttypes.h>
#include <time.h>

typedef uint32_t SHA256Digest[8];
typedef uint32_t SHA256MessageBlock[16];

enum SHA2StreamBehavior {
    /* Uses the time since last call to know if it should increase buffer size of just compute the hash now. */
    SHA2_AUTOMATIC,

    /* Will favor resizing the buffer over actually computing the hash until it absolutely has to. */
    SHA2_AGGRESSIVE_MEMORY_USAGE,

    /* Will favor just computing the hash over resizing the buffer. */
    SHA2_CONSERVATIVE_MEMORY_USAGE,
};

struct SHA2StreamState {
    /* Public fields. These are initialized by sha2*_stream_init. They are untouched by sha2*_stream_init_no_defaults. */
    size_t max_buf_size; /* Maximum buffer size in SHA256MessageBlocks. */
    enum SHA2StreamBehavior behavior; /* How SHA2 should buffer data. */

    /* Private fields */
    size_t _data_size;
    size_t _message_block_count;
    void *_message_blocks;

    struct timespec _last, _lastlast;
};

/** Perform the full SHA256 algorithm, including preprocessing. The resulting digest is "final" and shouldn't be mutated again.
 * This is best used for a small M that you can fit entirely into memory, this cannot be streamed.
 * @param M Message to hash.
 * @param nbytes Size of M in bytes.
 * @param H Digest to write to.
 */
void sha256(const void *M, size_t nbytes, SHA256Digest H);

/** Initializes a SHA2StreamState and SHA256Digest for use in streaming data.
 * @param st State to initialize. Call `sha256_stream_deinit`. Can also optionally be NULL.
 * @param H Digest to initialize.
*/
void sha256_stream_init(struct SHA2StreamState *st, SHA256Digest H);

/** Initializes a SHA2StreamState and SHA256Digest for use in streaming data. This will not override public fields in st.
 * @param st State to initialize. Call `sha256_stream_deinit`. Can also optionally be NULL.
 * @param H Digest to initialize.
*/
void sha256_stream_init_no_defaults(struct SHA2StreamState *st, SHA256Digest H);

/** Streams data into a current digest.
 * @param data Data to stream in.
 * @param nbytes Size of the data in bytes.
 * @param st State of stream.
 * @param H Current digest.
*/
void sha256_stream(const void *data, size_t nbytes, struct SHA2StreamState* st, SHA256Digest H);

/** Deinitializes a streaming state object.
 * @param st State to deinitialize. This will be free'd too and should not be used anymore.
 * @param H Digest to write final hash into.
*/
void sha256_stream_finish(struct SHA2StreamState *st, SHA256Digest H);

#endif /* __SHA256_H */