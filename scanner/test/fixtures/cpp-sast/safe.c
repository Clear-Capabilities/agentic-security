#include <stdio.h>
#include <string.h>

void ok_copy(const char *src) {
    char buf[64];
    strncpy(buf, src, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}

void ok_fmt(const char *user) {
    printf("%s", user);
}
