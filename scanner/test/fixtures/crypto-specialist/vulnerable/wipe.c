#include <string.h>
void use_key(void) {
    char secret[32];
    load_key(secret);
    memset(secret, 0, sizeof(secret));
}
