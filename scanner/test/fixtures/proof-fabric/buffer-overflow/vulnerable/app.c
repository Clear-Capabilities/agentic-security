/* Deliberately vulnerable: unbounded strcpy into a fixed-size stack buffer (classic CWE-121). */
#include <string.h>
int main(int argc, char **argv) {
    char buf[16];
    if (argc > 1) strcpy(buf, argv[1]);
    return 0;
}
