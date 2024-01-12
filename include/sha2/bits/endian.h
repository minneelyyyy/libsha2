#ifndef __SHA2_ENDIAN_H
#define __SHA2_ENDIAN_H

#define WRITE_32_BE(__v, __b)                                      \
    do {                                                           \
        ((unsigned char*)__b)[3] = (((uint32_t)__v) >> 0 ) & 0xff; \
        ((unsigned char*)__b)[2] = (((uint32_t)__v) >> 8 ) & 0xff; \
        ((unsigned char*)__b)[1] = (((uint32_t)__v) >> 16) & 0xff; \
        ((unsigned char*)__b)[0] = (((uint32_t)__v) >> 24) & 0xff; \
    } while(0)

#define READ_32_BE(__b) (((uint32_t)((unsigned char*)__b)[3] <<  0) | \
                         ((uint32_t)((unsigned char*)__b)[2] <<  8) | \
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

#define READ_64_BE(__b) ((((uint64_t)((unsigned char*)__b)[7]) <<  0) | \
                         (((uint64_t)((unsigned char*)__b)[6]) <<  8) | \
                         (((uint64_t)((unsigned char*)__b)[5]) << 16) | \
                         (((uint64_t)((unsigned char*)__b)[4]) << 24) | \
                         (((uint64_t)((unsigned char*)__b)[3]) << 32) | \
                         (((uint64_t)((unsigned char*)__b)[2]) << 40) | \
                         (((uint64_t)((unsigned char*)__b)[1]) << 48) | \
                         (((uint64_t)((unsigned char*)__b)[0]) << 56))

#endif /* __SHA2_ENDIAN_H */