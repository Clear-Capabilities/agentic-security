#include <cstdlib>

char* read_input() {
  return getenv("CMD");
}

void run_it() {
  char* cmd = read_input();
  system(cmd);
}
