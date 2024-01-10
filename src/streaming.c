#include <streaming.h>

/* This file is special.
 * It is not compiled as a traditional translation unit. instead, it is #included inside of any of the
 * algorithm files with some macros before to tell it what the name of each function and type should be. */

#ifndef SHA_ALGORITHM
#error attempt to compile streaming.c on its own or forgot to define necessary macros when including
#endif

#define MIN(__x, __y) ((__x) < (__y) ? (__x) : (__y))

#define msgblk_size_bytes(__x) (__x * sizeof(MESSAGE_BLOCK_T))

static void handle_dont_resize(const void *data, size_t nbytes, struct SHA2StreamState *st, DIGEST_T H) {
    while (nbytes != 0) {
        /* attempt to copy as much of nbytes as possible without going overflowing the buffer. */
        size_t amount = MIN(nbytes, msgblk_size_bytes(st->_message_block_cap) - st->_data_size);
        memcpy(((char*)st->_message_blocks) + st->_data_size, data, amount);

        /* Move forward in the buffer by amount */
        data = ((char*)data) + amount;
        nbytes -= amount;

        /* we added this much data to the buffer */
        st->_data_size += amount;

        /* If we didn't fill the buffer, then we can leave. */
        if (st->_data_size < msgblk_size_bytes(st->_message_block_cap))
            break;

        /* if we did, then we process the whole buffer. */
        SHA_F(st->_message_blocks, st->_message_block_cap, H);

        /* zero out buffer since padding is meant to be 0 bytes */
        memset(st->_message_blocks, 0, msgblk_size_bytes(st->_message_block_cap));
        st->_data_size = 0;

        /* tracks bytes written to the hash so far */
        st->_bytes_written += msgblk_size_bytes(st->_message_block_cap);
    }
}

static void resize_blocks(struct SHA2StreamState *st, size_t blocks) {
    st->_message_blocks = realloc(st->_message_blocks, msgblk_size_bytes(blocks));
    memset(st->_message_blocks + st->_data_size, 0, msgblk_size_bytes(blocks) - st->_data_size);
    st->_message_block_cap = blocks;
}

static void handle_possibly_resize(const void *data, size_t nbytes, struct SHA2StreamState *st, DIGEST_T H) {
    size_t blocks_required = nbytes / sizeof(MESSAGE_BLOCK_T) + (nbytes % sizeof(MESSAGE_BLOCK_T) != 0);
    size_t natural;

    /* The user is probably using a constant sized buffer. Allocate as big as it if allowed. */
    if (nbytes == st->_last_size) {
        if (!st->_message_block_cap < blocks_required)
            goto skip_resize;

        if (st->max_buf_cap)
            blocks_required = MIN(st->max_buf_cap, blocks_required);

        resize_blocks(st, blocks_required);

skip_resize:
        handle_dont_resize(data, nbytes, st, H);
        return;
    }

    natural = st->_message_block_cap * 3 / 2;

    if (st->max_buf_cap)
            natural = MIN(st->max_buf_cap, natural);
    
    resize_blocks(st, natural);

    handle_dont_resize(data, nbytes, st, H);
}

/* returns time in seconds */
static inline double average_times(struct SHA2StreamState *st, clock_t now) {
    return (((double) now + (double) st->_last + (double) st->_lastlast) / 3.0) * CLOCKS_PER_SEC;
}

static void not_enough_capacity(const void *data, size_t nbytes, struct SHA2StreamState *st, DIGEST_T H) {
    /* The buffer is the maximum capacity it's allowed, so it cannot possibly be resized. */
    if (st->max_buf_cap && st->_message_block_cap == st->max_buf_cap) {
        handle_dont_resize(data, nbytes, st, H);
        return;
    }

    if (st->_message_block_cap == 0)
        resize_blocks(st, 1);

    clock_t now = clock();

    if (average_times(st, now) > 0.1)
        /* user is infrequently meeting the buffers capacity. Don't bother with resizing it. */
        handle_dont_resize(data, nbytes, st, H);
    else
        /* user is very frequently overfilling the buffer. We should probably resize it. */
        handle_possibly_resize(data, nbytes, st, H);

    st->_lastlast = st->_last;
    st->_last = now;
    st->_last_size = nbytes;
}

void STREAM_F(const void *data, size_t nbytes, struct SHA2StreamState *st, DIGEST_T H) {
    if (st->_data_size + nbytes > msgblk_size_bytes(st->_message_block_cap))
        not_enough_capacity(data, nbytes, st, H);
    else {
        memcpy(((char*)st->_message_blocks) + st->_data_size, data, nbytes);
        st->_data_size += nbytes;
    }
}

void STREAM_INIT_F(struct SHA2StreamState *st, DIGEST_T H) {
    if (st != NULL) {
        st->max_buf_cap = 0;

        st->_message_block_cap = 0;
        st->_data_size = 0;
        st->_bytes_written = 0;
        st->_message_blocks = NULL;
        st->_last = 0;
        st->_last_size = 0;
    }

    init_digest(H);
}

void STREAM_INIT_NO_DEFAULTS_F(struct SHA2StreamState *st, DIGEST_T H) {
    if (st != NULL) {
        st->_message_block_cap = 0;
        st->_data_size = 0;
        st->_bytes_written = 0;
        st->_message_blocks = NULL;
        st->_last = 0;
        st->_last_size = 0;
    }

    init_digest(H);
}

void STREAM_FINISH_F(struct SHA2StreamState *st, DIGEST_T H) {
    size_t N;

    MESSAGE_BLOCK_T* blocks = padded_message(st->_message_blocks,
        st->_data_size,
        (st->_bytes_written + st->_data_size) * 8,
        &N);

    SHA_F(blocks, N, H);

    free(blocks);
    free(st->_message_blocks);

    /* this entire time we have probably been working with little endian numbers on most cpus.
     * this goes through each word in the final digest and flips the bytes. */
    for (size_t i = 0; i < 8; i++) {
        H[i] = READ_32_BE(&H[i]);
    }
}