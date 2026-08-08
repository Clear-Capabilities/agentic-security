#include <string.h>
void use_key(void) {
    char secret[32];
    load_key(secret);
    explicit_bzero(secret, sizeof(secret));
}
