// sc.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(int argc, char **argv) {
    long nr = atol(argv[1]);
    long r = syscall(nr, 0, 0, 0, 0, 0, 0);
    printf("syscall %ld -> ret=%ld errno=%d (%s)\n", nr, r, errno, strerror(errno));
    return 0;
}