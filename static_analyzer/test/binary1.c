#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

int main(void)
{
    const char msg[] = "Process syscall example\n";

    /* write() */
    syscall(SYS_write, STDOUT_FILENO, msg, sizeof(msg) - 1);

    /* getpid() */
    syscall(SYS_getpid);

    /* getppid() */
    syscall(SYS_getppid);

    /* gettid() */
    syscall(SYS_gettid);

    /* sched_yield() */
    syscall(SYS_sched_yield);

    /* getpgid() */
    syscall(SYS_getpgid, 0);

    /* getsid() */
    syscall(SYS_getsid, 0);

    return 0;
}