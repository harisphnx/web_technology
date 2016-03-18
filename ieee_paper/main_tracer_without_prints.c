#include<ctype.h>
#include<arpa/inet.h>
#include<syscall.h>
#include<errno.h>
#include<netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<stdio.h>
#include<sys/ptrace.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>
#include<sys/user.h>
#include<sys/syscall.h>   /* For SYS_write etc */
#include<stdlib.h>

#define ORIG_RAX 15
#define SYSCALL_MAXARGS 6
#define RDI 14

int sub_1_str(char *,int , char *,int);
int sub_2_str(char *, int, char *, int, char *, int, char *, int);
int numbers(char *, int);

int sub_1_str(char * actual_str, int n1, char * substr, int n2)
{
	int i, j, flag;
	for (i = 0; i <= n1 - n2; i++)
	{
        	for (j = i; j < i + n2; j++)
        	{
			flag = 1;
			if (actual_str[j] != substr[j - i])
			{
				flag = 0;
				break;
			}
		}
		if (flag == 1)
			break;
	}
	if (flag == 1)
		return 1;
	else
		return 0;
}

int sub_2_str(char * actual_str, int n1, char * substr1, int n2, char * substr2, int n3, char * substr3, int n4)
{
        int i, j, flag;
	for (i = 0; i <= n1 - n2; i++)
	{
        	for (j = i; j < i + n2; j++)
        	{
			flag = 1;
			if (actual_str[j] != substr1[j - i])
			{
				flag = 0;
				break;
			}
		}
		if (flag == 1)
			break;
	}
	if(flag == 0)
	{
		for (i = 0; i <= n1 - n3; i++)
		{
	        	for (j = i; j < i + n3; j++)
	        	{
				flag = 1;
				if (actual_str[j] != substr2[j - i])
				{
					flag = 0;
					break;
				}
			}
			if (flag == 1)
				break;
		}
	}	
	if(flag == 0)
	{
		for (i = 0; i <= n1 - n4; i++)
		{
	        	for (j = i; j < i + n4; j++)
	        	{
				flag = 1;
				if (actual_str[j] != substr3[j - i])
				{
					flag = 0;
					break;
				}
			}
			if (flag == 1)
				break;
		}
	}
        if (flag == 1)
                return 1;
        else
                return 0;
}


int numbers(char * actual_str, int n1)
{
	int count=0, i;
	for(i = 0;i < n1; i++)
	{
		if(isdigit(actual_str[i]))
			count++;
	}
	return count;
}

int main()
{
	//**********declarations and memory allocations**********//
	ssize_t size;
	long sys_call_number, temp_long;
	int status, temp, i, j, k, flag, inode = 0, eq;
	int number_count, count;
	unsigned int a, b, c, d;
	
	struct sockaddr_in ip_addr_struct;
	socklen_t ip_addr_structlen = sizeof(ip_addr_struct);
	struct user_regs_struct regs;

	struct sockaddr_in* connect_struct;
	
	char* filepath = malloc(256);
	char* char_temp = malloc(64);
        char* line = malloc(256);
        char* command = malloc(64);
	char* message = malloc(1024);
	char* connect_ip = malloc(64); 
	char* ip_addr = malloc(64);
	char* dummy = malloc(1024);

	char* tcp_path = malloc(32);
	char* udp_path = malloc(32);
	char* fdpath = malloc(32);
	
	char* temp_char1,* temp_char2;
	char sys_path[] = "/sys";

	char blacklisted_ip[][8] = { "103.7.29.211",
"103.7.29.215",
"117.21.191.47",
"121.14.212.18",
"103.250.12.21",
"176.31.228.6",
"200.27.164.10",
"183.136.232.16",
"184.51.126.32" };	
	pid_t proc;

	for(i = 0;i < 1023; i++)
	{
		dummy[i] = '\0';
	} 

	
	//**********getting pid and attaching to process and initializing some file pointers**********//
	scanf("%d",&proc);

	ptrace(PTRACE_ATTACH,proc, NULL, NULL);

	//**********starting the trace process**********//

	//The system call number used in switch() case to determine particular system calls// 
	while(1)
	{
        	wait(&status);
        	if(WIFEXITED(status))
		{
		/*	free(filepath);
			free(char_temp);
			free(line);
			free(command);
			free(message);
			free(connect_ip);
			free(ip_addr);
                */	printf("****Process exited****\n");
			break;
        	}
                ptrace(PTRACE_GETREGS, proc, NULL, &regs);
                sys_call_number = regs.orig_rax;

		switch(sys_call_number)
		{
			case 0:
				//printf("read\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
				filepath[size] = '\0';
                                //printf("File-%s-\n", filepath);
				flag = 1;
				for(i = 0;i < 4;i++)
				{
					if(filepath[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
					temp_long = 0;
        	                        ptrace(PTRACE_POKEDATA, proc, regs.rdi , &temp_long);
				}
				else
				{
					temp_char2 = message;
					j = 0;
	                                while( j < (regs.rdx/8) )
	                                {
	                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
	                                        memcpy(temp_char2, &temp_long, 8);
	                                        temp_char2 += 8;
	                                        ++j;
	                                }
					message[regs.rdx] = '\0';
	                         //       printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				memcpy(filepath, dummy, 256);
				break;
			case 1:
				//printf("write\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
				filepath[size] = '\0';
				//printf("File-%s-\n", filepath);
				flag = 1;
				for(i = 0;i < 4;i++)
				{
					if(filepath[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
					temp_long = 0;
        	                        ptrace(PTRACE_POKEDATA, proc, regs.rdi , &temp_long);
				}
				else
				{
	                                temp_char2 = message;
	                                j = 0;
	                                while( j < (regs.rdx/8) )
	                                {
	                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
	                                        memcpy(temp_char2, &temp_long, 8);
	                                        temp_char2 += 8;
	                                        ++j;
	                                }
	                                message[regs.rdx] = '\0';
	                         //       printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				memcpy(filepath, dummy, 256);
				break;
			case 45:
				//printf("recvfrom\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				//printf("Inode - %d\n",inode);
				
				temp_char2 = message;
                                j = 0;
                                while( j < (regs.rdx/8) )
                                {
                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
                                        memcpy(temp_char2, &temp_long, 8);
                                        temp_char2 += 8;
                                        ++j;
                                }
				temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
				memcpy(temp_char2, &temp_long, regs.rdx - (j*8) );
                                message[regs.rdx] = '\0';
				flag = 0;
				flag = sub_1_str(message, regs.rdx, "eval(unescape(", 14);
				if(flag == 1)
				{
					//obfuscated js present (  eval(unescape(  ) )
				//	printf("eval present pppp\n");
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
	                                j = 0;
					temp_long = 0;
	                                while( j < 4 )
	                                {
	                                        ptrace(PTRACE_POKEDATA, proc, regs.rsi + (j*8) , &temp_long);
	                                        ++j;
	                                }
					temp_long = ptrace(PTRACE_POKEDATA, proc, regs.rsi + (j*8) , &temp_long);
				}
				else if(flag == 0)
				{
					flag = sub_2_str(message, regs.rdx, "parseInt", 8, "String.fromCharCode", 19, "eval(", 5);
					if( flag == 1)
					{
						number_count = numbers(message, regs.rdx);
				//		printf("number_count- %d",number_count);
						if( number_count > 1000)
						{
							//obfuscated js present ( numbers with parsint() or String.fromCharCode()
							system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
				//			printf("numbers and parseInt or String.fromCharCode present pppp\n");
	        	                        	j = 0;
							temp_long = 0;
	                		                while( j < (regs.rdx/8) )
			                                {
			                                        ptrace(PTRACE_POKEDATA, proc, regs.rsi + (j*8) , &temp_long);
	                		                        ++j;
	                                		}
							temp_long = ptrace(PTRACE_POKEDATA, proc, regs.rsi + (j*8) , &temp_long);
						}
					}
				}
				else
				{	
                                //	printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				break;
			case 47:
				//printf("recvmsg\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				//printf("Inode - %d\n",inode);
				break;
			case 44:
				//printf("sendto\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				//printf("Inode - %d\n",inode);

				temp_char2 = message;
                                j = 0;
                                while( j < (regs.rdx/8) )
                                {
                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
                                        memcpy(temp_char2, &temp_long, 8);
                                        temp_char2 += 8;
                                        ++j;
                                }
				temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
				memcpy(temp_char2, &temp_long, regs.rdx - (j*8) );
                                message[regs.rdx] = '\0';
                                //printf("Message-%s-\n\n", message);
				memcpy(message, dummy, 1024);
				break;
			case 46:
				//printf("sendmsg\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 41:
				//printf("socket\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 42:
				//printf("connect\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				connect_struct = (struct sockaddr_in*)connect_ip;
				j = 0;
				while( j < (regs.rdx/8) )
                                {
                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
                                        memcpy(connect_ip, &temp_long, 8);
                                        connect_ip += 8;
                                        ++j;
                                }
				inet_ntop(AF_INET, &(connect_struct->sin_addr), ip_addr, 64);
				//printf("Connect To IP-%s-\n",ip_addr);
				//rewind(blacklisted_ip);
				/*printf("%d",blacklisted_ip);
				printf("%p",fgets(line, 12, blacklisted_ip));
				printf("%s",line);*/
				j = 0;
				while(j < 558)
				{
					//printf("%s", blacklisted_ip[j++]);
					if( !strcmp(ip_addr, blacklisted_ip[j++]) )
					{
						system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
						j = 0;
						temp_long = 0;
						while( j < (regs.rdx/8) )
                                		{
		                                        ptrace(PTRACE_POKEDATA, proc, regs.rsi + (j*8) , &temp_long);
		                                        ++j;
                		                }
					}
				}
				break;
			case 49:
				//printf("bind\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				connect_struct = (struct sockaddr_in*)connect_ip;
                                j = 0;
                                while( j < (regs.rdx/8) )
                                {
                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rsi + (j*8) , NULL);
                                        memcpy(connect_ip, &temp_long, 8);
                                        connect_ip += 8;
                                        ++j;
                                }
                                inet_ntop(AF_INET, &(connect_struct->sin_addr), ip_addr, 64);
                                //printf("Sockfd %llu binds to IP %s-\n\n", regs.rdi, ip_addr);
				break;
			case 2:
				//printf("open\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				temp_char2 = message;
				count = 0;
                                temp_char1 = (char*)&temp_long;
                                flag = 1;
                                j = 0;
                                while(flag == 1)
                                {
                                        temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rdi + (j*8) , NULL);
                                        memcpy(temp_char2, temp_char1, 8);
                                        for(i = 0;i < 8;i++)
                                        {
                                                if(temp_char1[i] == '\0')
                                                {
                                                        flag = 0;
                                                        temp_char2[i] = '\0';
                                                }
                                        }
                                        temp_char2 += 8;
                                        ++j;
					count += 1;
                                }
                                //printf("FIlepath -%s-\n\n", message);
				flag = 1;
				for(i = 0;i < 4;i++)
				{
					if(message[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
	                                flag = 1;
        	                        j = 0;
					temp_long = 0;
                        	        while(count != 0)
	                                {
        	                                ptrace(PTRACE_POKEDATA, proc, regs.rdi + (j*8) , &temp_long);
                	                        ++j;
                        	        }
				}
				memcpy(message, dummy, 1024);
				memcpy(filepath, dummy, 256);
				break;
			case 3:
				//printf("close\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("Filepath -%s-\n\n", filepath);
				flag = 1;
				for(i = 0;i < 4;i++)
				{
					if(filepath[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
					temp_long = 0;
        	                        ptrace(PTRACE_POKEDATA, proc, regs.rdi , &temp_long);
				}
				memcpy(filepath, dummy, 256);
				break;
			case 5:
				//printf("fstat\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("On File -%s-\n\n", filepath);
				flag = 1;
				for(i = 0;i < 12;i++)
				{
					if(filepath[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
					temp_long = 0;
        	                        ptrace(PTRACE_POKEDATA, proc, regs.rdi , &temp_long);
				}
				memcpy(filepath, dummy, 256);
				break;
			case 8:
				//printf("lseek\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                //printf("On File -%s-\n\n", filepath);
				flag = 1;
				for(i = 0;i < 4;i++)
				{
					if(filepath[i] != sys_path[i])
					{
						flag = 0;
						break;
					}
				}
				if(flag == 1)
				{
					//filepath has /sys
					system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
					temp_long = 0;
        	                        ptrace(PTRACE_POKEDATA, proc, regs.rdi , &temp_long);
				}
				memcpy(filepath, dummy, 256);
				break;
			case 9:
				//printf("mmap\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 11:
				//printf("munmap\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 12:
				//printf("brk\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 202:

				//printf("futex\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rdi , NULL);
				//printf("-%lu-\n\n",temp_long);
				break;
			case 22:
				//printf("pipe\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 59:
				//printf("execve\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
		}
         	ptrace(PTRACE_SYSCALL,proc, NULL, NULL);
	}
	return 0;
}
