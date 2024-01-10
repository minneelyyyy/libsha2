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
    { "This sentence is exactly 512 bits long, in case you didn't know.", "c31cccd49815d575d0389931599a5796a5b9b8371e4498711680d1a8863a6767" },
    {
        "static void _sha256(const SHA256MessageBlock *M, size_t N, SHA256Digest H) {\n"
        "    uint32_t W[64];\n"
        "    uint32_t a, b, c, d, e, f, g, h, T1, T2;\n"
        "\n"
        "    for (size_t i = 1; i <= N; i++) {\n"
        "        for (size_t t = 0; t < 16; t++) {\n"
        "            W[t] = READ_32_BE(&M[i - 1][t]);\n"
        "        }\n"
        "\n"
        "        for (size_t t = 16; t < 64; t++) {\n"
        "            W[t] = lsigma1(W[t - 2]) + W[t - 7] + lsigma0(W[t - 15]) + W[t - 16];\n"
        "        }\n"
        "\n"
        "        a = H[0];\n"
        "        b = H[1];\n"
        "        c = H[2];\n"
        "        d = H[3];\n"
        "        e = H[4];\n"
        "        f = H[5];\n"
        "        g = H[6];\n"
        "        h = H[7];\n"
        "\n"
        "        for (size_t t = 0; t < 64; t++) {\n"
        "            T1 = h + sigma1(e) + Ch(e, f, g) + K[t] + W[t];\n"
        "            T2 = sigma0(a) + Maj(a, b, c);\n"
        "            h = g;\n"
        "            g = f;\n"
        "            f = e;\n"
        "            e = d + T1;\n"
        "            d = c;\n"
        "            c = b;\n"
        "            b = a;\n"
        "            a = T1 + T2;\n"
        "        }\n"
        "\n"
        "        H[0] = a + H[0];\n"
        "        H[1] = b + H[1];\n"
        "        H[2] = c + H[2];\n"
        "        H[3] = d + H[3];\n"
        "        H[4] = e + H[4];\n"
        "        H[5] = f + H[5];\n"
        "        H[6] = g + H[6];\n"
        "        H[7] = h + H[7];\n"
        "    }\n"
        "}", "ea49de665af07645d3d636a5dd78d8ec9a2af7d3ffb942b7501e9fe43378de00"
    }
};

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
