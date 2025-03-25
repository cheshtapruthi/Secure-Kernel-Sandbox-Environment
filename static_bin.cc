#include <sys/prctl.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>

int main(int argc, char* argv[]) {
  char buf[1024];
  size_t total_bytes = 0U;

  prctl(PR_SET_NAME, "static_bin");

  fprintf(stderr, "=============================\n");
  fprintf(stderr, "Starting file capitalization\n");
  fprintf(stderr, "=============================\n");
  fflush(nullptr);

  for (;;) {
    ssize_t sz = read(STDIN_FILENO, buf, sizeof(buf));
    if (sz < 0) {
      perror("read");
      break;
    }
    if (sz == 0) {
      break;
    }
    for (int i = 0; i < sz; i++) {
      buf[i] = toupper(buf[i]);
    }
    write(STDOUT_FILENO, buf, sz);
    total_bytes += sz;
  }

  fprintf(stderr, "=============================\n");
  fprintf(stderr, "Converted: %zu bytes\n", total_bytes);
  fprintf(stderr, "=============================\n");
  fflush(nullptr);
  return 0;
}
