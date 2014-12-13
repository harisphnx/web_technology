#include<stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>   /* For SYS_write etc */

#define ORIG_RAX 15

int main()
{
        long sys_call_number;
        int status;
	struct user_regs_struct regs;
        pid_t proc;
        scanf("%d",&proc);

        ptrace(PTRACE_ATTACH,proc, NULL, NULL);

        while(1)
        {
                wait(&status);
                if(WIFEXITED(status))
                {
                        printf("****Process exited****\n");
                        break;
                }
		ptrace(PTRACE_GETREGS, proc, NULL, &regs);
		sys_call_number = regs.orig_rax;
		printf("%lu\n", sys_call_number);
		ptrace(PTRACE_SYSCALL, proc, NULL, NULL);
	}

}

