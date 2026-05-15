#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void bad_copy(const char *src) {
    char buf[64];
    strcpy(buf, src);          /* CWE-120 */
    strcat(buf, " extra");     /* CWE-120 */
}

void bad_fmt(const char *user) {
    printf(user);              /* CWE-134 format string */
}

void bad_exec(const char *user) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user);
    system(cmd);               /* CWE-78 */
}

void bad_mem(const char *src, size_t user_len) {
    char dst[16];
    memcpy(dst, src, user_len);  /* CWE-787 */
}

unsigned int generate_session_token(void) {
    srand(time(NULL));                    /* CWE-338 — predictable seed for security */
    unsigned int session_token = rand();  /* CWE-338 — non-CSPRNG for security token */
    return session_token;
}
