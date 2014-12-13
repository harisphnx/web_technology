#include<stdio.h>
#include<sys/ptrace.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>
#include<sys/user.h>
#include<sys/syscall.h>   /* For SYS_write etc */

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
//         	sys_call_number = ptrace(PTRACE_PEEKUSER, proc, sizeof(long) * ORIG_RAX, NULL);
//         	printf("System call number %ld\n",sys_call_number);

		switch(sys_call_number)
		{
			case 0:
				printf("read\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 1:
				printf("write\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 45:
				printf("recvfrom\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 47:
				printf("recvmsg\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 44:
				printf("sendto\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 46:
				printf("sendmsg\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 41:
				printf("socket\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 42:
				printf("connect\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 49:
				printf("bind\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 2:
				printf("open\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 3:
				printf("close\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 5:
				printf("fstat\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 8:
				printf("lseek\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 9:
				printf("mmap\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 11:
				printf("munmap\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 12:
				printf("brk\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 202:
				printf("futex\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 22:
				printf("pipe\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 59:
				printf("execve\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
			case 39:
				printf("getpid\n");
				printf("%llu - %llu - %llu - %llu\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
				break;
		}
         	ptrace(PTRACE_SYSCALL,proc, NULL, NULL);
	}
	return 0;
}
 

