#include<sys/ptrace.h>
#include<sys/syscall.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>
#include<sys/user.h>
#include<stdio.h>
int main()
{
        pid_t fire_proc;
        int signal, syscall,i=0;
        struct user_regs_struct u_in;
//	fire_proc = 4801;	
	scanf("%d", &fire_proc);

	ptrace(PTRACE_ATTACH, fire_proc, 0, 0);
	ptrace(PTRACE_SYSCALL, fire_proc, 0, 0);
        while(i<100)
        {
		
//		sleep(0.5);
		
//		printf("%d",fire_proc);
                wait(&signal);
                if (WIFEXITED(signal))          //The child process exited
        	        break;
                ptrace(PTRACE_GETREGS, fire_proc, 0, &u_in);
		printf("%llu ",u_in.orig_rax);
                syscall = ptrace(PTRACE_PEEKUSER, fire_proc, sizeof(long)*u_in.orig_rax);
                printf("%d=", syscall);
//		sleep(1);
		ptrace(PTRACE_SYSCALL, fire_proc, 0, 0);
	//	ptrace(PTRACE_CONT, fire_proc, NULL, 0);
		i++;        
}
	ptrace(PTRACE_DETACH, fire_proc, 0, 0);

}
