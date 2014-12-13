#include<sys/ptrace.h>
#include <sys/syscall.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>
#include<sys/user.h>
#include<stdio.h>
int main()
{
	pid_t fire_proc;
	int signal, syscall;
	struct user_regs_struct u_in;
	
	fire_proc =  fork();

	if(fire_proc == 0)
	{
		ptrace(PTRACE_TRACEME);
		FILE *fp = fopen("test.txt", "r");
		execl("/bin/ls", "ls", NULL);
	}
	else
	{
		while(1)
		{
//			ptrace(PTRACE_ATTACH, fire_proc, 0, 0);
    			ptrace(PTRACE_SYSCALL, fire_proc, 0, 0);
			wait(&signal);
			if (WIFEXITED(signal))		//The child process exited
				break;
        		ptrace(PTRACE_GETREGS, fire_proc, 0, &u_in);
			syscall = ptrace(PTRACE_PEEKUSER, fire_proc, 16*u_in.orig_rax);
			printf("%d-", syscall);
		}
	}

}
