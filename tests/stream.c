#include <sha256.h>
#include <streaming.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    struct SHA2StreamState st;
    SHA256Digest digest;
    char buffer[512];

    st.max_buf_cap = 1;
    st.behavior = SHA2_AUTOMATIC;

    sha256_stream_init_no_defaults(&st, digest);

    sha256_stream("The quick brown fox", strlen("The quick brown fox"), &st, digest);
    sha256_stream(" jumps ", strlen(" jumps "), &st, digest);
    sha256_stream("over the lazy dog.", strlen("over the lazy dog."), &st, digest);
    sha256_stream("HTML is a horrible programming language.", strlen("HTML is a horrible programming language."), &st, digest);

    sha256_stream_finish(&st, digest);

    sha256tos(buffer, digest);

    printf("%s\n", buffer);

    return 0;
}