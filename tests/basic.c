#include <sha256.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

struct test {
    const char *text;
    const char *hash;
};

struct test tests[] = {
    { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { "The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    { "The quick brown fox jumps over the lazy dog.", "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c" },
};

char *sha256tos(char *out, SHA256Digest digest) {
    char buffer[3] = "";

    *out = '\0';

    for (size_t i = 0; i < 256 / 8; i++) {
	    snprintf(buffer, 3, "%02hhx", ((char*)digest)[i]);
	    strcat(out, buffer);
    }

    return out;
}

int main(void) {
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        SHA256Digest digest;
        char digest_str[64];

        sha256(tests[i].text, strlen(tests[i].text), digest);
        printf("\"%s\" => %64s\n", tests[i].text, sha256tos(digest_str, digest));

        assert(!strcmp(tests[i].hash, digest_str));
    }

    return 0;
}
