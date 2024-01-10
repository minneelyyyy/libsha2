#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha256.h>
#include <streaming.h>

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

    sha256_stream_init(&st, digest);

    while (bytes_read = fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), f)) {
        sha256_stream(buffer, bytes_read, &st, digest);
    }

    sha256_stream_finish(&st, digest);

    sha256tos(buffer, digest);

    printf("%s  %s\n", buffer, argv[1]);

    fclose(f);

    return 0;
}
