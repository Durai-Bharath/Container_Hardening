#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

int main(void)
{
    const char msg[] = "Testing different Linux syscalls!\n";
    char cwd[256];

    /* write() */
    syscall(SYS_write, STDOUT_FILENO, msg, sizeof(msg) - 1);

    /* mkdir() */
    syscall(SYS_mkdir, "syscall_test", 0755);

    /* chdir() */
    syscall(SYS_chdir, "syscall_test");

    /* getcwd() */
    syscall(SYS_getcwd, cwd, sizeof(cwd));

    /* write() current directory */
    syscall(SYS_write, STDOUT_FILENO, cwd, sizeof(cwd));

    /* chdir() back */
    syscall(SYS_chdir, "..");

    /* unlink() - remove directory entry/file */
    syscall(SYS_unlink, "syscall_test");

    /* nanosleep() */
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;

    syscall(SYS_nanosleep, &ts, NULL);

    /* brk() */
    syscall(SYS_brk, 0);

    return 0;
}