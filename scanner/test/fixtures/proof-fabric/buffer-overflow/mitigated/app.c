/* Mitigated: the copy is bounded to the destination buffer's own size and always NUL-terminated. */
#include <string.h>
int main(int argc, char **argv) {
    char buf[16];
    if (argc > 1) {
        size_t n = strlen(argv[1]);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
        memcpy(buf, argv[1], n);
        buf[n] = '\0';
    }
    return 0;
}
