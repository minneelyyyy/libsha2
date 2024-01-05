#include <sha256.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

int main(void) {
    SHA256Digest digest;
    const char *data = "abc";

    sha256(data, strlen(data), digest);

    printf("\"%s\" => ", data);

    for (size_t i = 0; i < 256 / 8; i++) {
        printf("%hhx", ((char*)digest)[i]);
    }

    printf("\n");

    return 0;
}
