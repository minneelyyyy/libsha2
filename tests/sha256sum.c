#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha256.h>
#include <streaming.h>

char *sha256tos(char *out, SHA256Digest digest) {
    char buffer[3] = "";

    *out = '\0';

    for (size_t i = 0; i < 256 / 8; i++) {
	    snprintf(buffer, 3, "%02hhx", ((char*)digest)[i]);
	    strcat(out, buffer);
    }

    return out;
}

int main(int argc, char **argv) {
    FILE *f;
    char buffer[4096];
    size_t bytes_read;
    struct SHA2StreamState st;
    SHA256Digest digest;

    if (argc < 2) {
        fprintf(stderr, "USAGE: %s <FILE PATH>\n", argv[0]);
        return 0;
    }

    f = fopen(argv[1], "rb");

    st.max_buf_cap = 1;
    st.behavior = SHA2_AUTOMATIC;

    sha256_stream_init_no_defaults(&st, digest);

    while (bytes_read = fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), f)) {
        sha256_stream(buffer, bytes_read, &st, digest);
    }

    sha256_stream_finish(&st, digest);

    sha256tos(buffer, digest);

    printf("%s  %s\n", buffer, argv[1]);

    fclose(f);

    return 0;
}
