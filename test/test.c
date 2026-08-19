#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(void)
{
    const char msg[] = "Hello syscall analyzer!\n";

    /* write() */
    syscall(SYS_write, STDOUT_FILENO, msg, sizeof(msg) - 1);

    /* getpid() */
    syscall(SYS_getpid);

    /* getuid() */
    syscall(SYS_getuid);

    /* getppid() */
    syscall(SYS_getppid);

    /* close() */
    syscall(SYS_close, STDOUT_FILENO);

    return 0;
}