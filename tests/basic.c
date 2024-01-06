#include <sha256.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

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
    char str[512];
    SHA256Digest digest;

    const char *abc = "abc";
    const char *fox = "The quick brown fox jumps over the lazy dog";
    const char *fox_punc = "The quick brown fox jumps over the lazy dog.";

    sha256("", 0, digest);
    printf("\"%s\" => %s\n", "", sha256tos(str, digest));
    assert(!strcmp("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", str));

    sha256(abc, strlen(abc), digest);
    printf("\"%s\" => %s\n", abc, sha256tos(str, digest));
    assert(!strcmp("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", str));

    sha256(fox, strlen(fox), digest);
    printf("\"%s\" => %s\n", fox, sha256tos(str, digest));
    assert(!strcmp("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", str));

    sha256(fox_punc, strlen(fox_punc), digest);
    printf("\"%s\" => %s\n", fox_punc, sha256tos(str, digest));
    assert(!strcmp("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c", str));

    return 0;
}
