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

	char blacklisted_ip[][557] = { "103.7.29.211",
"103.7.29.215",
"117.21.191.47",
"121.14.212.18",
"103.250.12.21",
"176.31.228.6",
"200.27.164.10",
"183.136.232.16",
"111.177.111.7",
"60.221.255.11",
"60.221.255.13",
"203.205.148.10",
"203.205.148.11",
"203.205.148.12",
"203.205.148.13",
"203.205.148.14",
"203.205.148.15",
"46.30.42.178",
"54.69.90.62",
"70.38.40.185",
"92.63.100.128",
"210.71.194.2",
"184.173.98.24",
"54.68.142.187",
"184.173.161.22",
"174.35.27.71",
"54.231.0.249",
"192.185.77.13",
"192.185.77.15",
"69.58.188.40",
"95.213.148.22",
"91.218.228.17",
"122.228.251.9",
"50.87.146.184",
"50.97.44.131",
"109.201.141.22",
"8.37.231.20",
"72.21.195.161",
"205.234.175.15",
"54.230.193.45",
"208.131.135.1",
"198.7.58.216",
"222.186.20.12",
"54.230.194.21",
"74.120.16.149",
"221.235.189.16",
"54.230.192.74",
"54.230.195.35",
"54.239.152.18",
"54.230.192.14",
"54.230.194.15",
"185.32.188.20",
"174.35.27.77",
"104.28.5.37",
"222.186.130.28",
"23.73.181.34",
"23.73.181.26",
"23.62.7.152",
"23.62.236.187",
"23.62.236.162",
"23.62.7.162",
"23.73.181.43",
"23.62.7.138",
"23.73.181.48",
"23.62.6.144",
"23.73.181.35",
"23.62.236.176",
"23.73.181.33",
"23.15.8.26",
"198.232.124.24",
"8.37.235.11",
"46.254.18.90",
"179.43.162.22",
"188.93.91.22",
"188.93.91.23",
"179.43.162.23",
"176.119.0.211",
"176.119.0.209",
"176.119.0.210",
"179.43.162.19",
"176.119.0.205",
"179.43.162.23",
"179.43.162.22",
"176.119.0.207",
"178.32.238.21",
"198.50.196.25",
"178.32.161.83",
"178.32.238.21",
"37.59.93.37",
"91.202.63.36",
"180.153.235.20",
"222.186.60.3",
"122.226.102.7",
"218.87.111.75",
"183.57.148.24",
"221.209.235.17",
"58.218.211.29",
"218.75.110.13",
"183.61.19.169",
"222.186.60.60",
"119.188.139.11",
"218.75.159.18",
"54.230.192.97",
"184.51.126.66",
"162.210.193.26",
"121.52.234.10",
"23.21.206.35",
"146.185.253.17",
"23.62.6.194",
"23.62.6.74",
"23.62.6.35",
"23.62.6.48",
"23.62.6.64",
"23.62.6.82",
"23.62.236.185",
"23.62.6.67",
"23.62.6.65",
"23.62.6.73",
"23.62.6.97",
"23.62.6.43",
"23.62.236.113",
"184.172.2.121",
"218.75.155.39",
"37.59.34.74",
"218.23.238.28",
"116.255.167.6",
"218.93.127.10",
"125.66.111.13",
"218.75.155.41",
"198.46.91.101",
"94.73.151.110",
"93.93.112.68",
"54.84.219.162",
"144.76.61.176",
"211.172.241.10",
"50.23.68.85",
"94.228.215.77",
"221.2.194.236",
"54.197.235.95",
"192.254.234.29",
"118.218.219.17",
"107.22.245.5",
"118.122.37.10",
"104.28.23.59",
"222.186.19.21",
"108.175.154.3",
"104.28.14.104",
"185.36.100.16",
"69.195.124.22",
"198.7.61.118",
"173.10.20.97",
"107.22.183.10",
"54.243.252.16",
"104.28.9.55",
"54.230.23.116",
"54.208.13.153",
"74.209.245.12",
"185.38.84.18",
"54.68.85.18",
"122.225.100.20",
"122.225.98.19",
"94.242.195.14",
"37.140.192.18",
"67.228.0.99",
"208.109.216.5",
"209.90.88.138",
"83.223.106.9",
"192.185.77.12",
"60.218.20.4",
"61.147.75.7",
"104.28.13.51",
"95.215.225.21",
"192.185.77.15",
"66.114.52.20",
"107.20.176.51",
"188.122.76.10",
"74.220.207.18",
"123.125.65.16",
"221.194.130.1",
"220.181.159.9",
"50.22.59.197",
"218.93.127.65",
"115.236.22.24",
"23.15.7.91",
"54.230.195.25",
"54.230.195.23",
"54.192.193.15",
"115.71.1.208",
"218.28.104.67",
"50.63.176.74",
"94.75.244.139",
"58.64.202.244",
"54.68.226.215",
"91.121.192.69",
"104.131.244.8",
"91.142.215.2",
"62.85.163.67",
"5.2.16.210",
"93.189.32.251",
"54.83.36.223",
"121.10.143.22",
"108.168.149.4",
"212.129.43.95",
"58.61.157.235",
"59.55.141.93",
"177.55.96.224",
"50.18.172.232",
"115.28.22.107",
"8.37.234.6",
"217.23.7.68",
"92.53.98.156",
"195.154.168.14",
"118.218.136.5",
"42.121.253.21",
"61.143.198.11",
"192.185.236.19",
"183.136.235.1",
"111.177.111.8",
"210.71.194.1",
"66.114.52.7",
"121.78.56.151",
"54.231.2.41",
"192.185.77.13",
"115.238.226.8",
"50.97.49.243",
"8.37.231.19",
"54.231.8.241",
"14.17.97.112",
"74.120.16.148",
"54.230.194.18",
"54.230.194.19",
"54.230.195.24",
"54.230.194.13",
"4.27.23.126",
"212.52.82.53",
"104.28.4.37",
"23.73.181.25",
"23.73.181.32",
"23.62.7.17",
"23.62.7.8",
"23.73.181.42",
"23.73.181.19",
"23.73.181.41",
"23.73.181.24",
"23.62.7.32",
"23.62.7.27",
"23.62.236.178",
"23.62.236.179",
"8.37.235.12",
"72.21.81.128",
"178.32.158.14",
"178.32.158.13",
"5.39.5.227",
"222.173.194.2",
"116.11.254.24",
"222.186.60.23",
"123.235.33.12",
"218.85.133.39",
"54.230.192.12",
"162.210.193.29",
"23.62.236.48",
"23.23.138.196",
"183.111.148.3",
"75.101.156.24",
"50.19.236.133",
"23.23.100.24",
"104.28.22.59",
"212.7.200.83",
"104.28.15.104",
"69.16.175.10",
"54.68.145.87",
"183.111.141.8",
"72.167.131.12",
"54.86.65.100",
"104.28.8.55",
"198.187.31.10",
"122.226.76.78",
"95.211.187.13",
"192.185.236.2",
"95.213.148.78",
"54.219.135.16",
"174.35.27.70",
"107.20.176.23",
"54.68.183.183",
"91.222.137.84",
"174.132.120.12",
"54.230.192.23",
"54.68.130.17",
"190.228.29.82",
"61.177.180.18",
"188.94.90.4",
"1.234.66.30",
"218.146.254.3",
"104.28.17.41",
"207.241.226.10",
"188.121.46.12",
"67.210.209.82",
"222.186.39.46",
"176.121.11.90",
"113.10.149.12",
"219.238.235.4",
"203.183.23.72",
"192.174.55.97",
"187.84.225.36",
"202.97.174.82",
"89.111.176.31",
"123.249.24.18",
"195.234.237.4",
"188.165.146.11",
"213.186.33.19",
"192.254.185.11",
"174.137.173.7",
"69.58.188.39",
"54.240.235.89",
"23.73.181.18",
"54.230.195.16",
"199.101.114.2",
"74.120.16.155",
"54.230.192.19",
"54.239.152.81",
"204.45.61.27",
"23.62.6.179",
"23.15.8.208",
"23.15.8.211",
"23.15.8.233",
"108.163.210.2",
"23.62.6.104",
"23.15.8.225",
"23.15.8.224",
"184.51.126.18",
"8.37.234.12",
"208.111.161.24",
"5.39.5.237",
"178.32.238.22",
"178.32.238.20",
"37.59.93.36",
"178.32.161.86",
"222.186.60.31",
"222.186.60.10",
"211.144.88.38",
"123.235.33.16",
"222.163.80.69",
"23.91.112.4",
"23.15.9.43",
"58.222.20.238",
"149.174.97.12",
"23.73.181.51",
"23.73.181.40",
"23.73.181.49",
"23.73.181.27",
"54.235.175.14",
"23.78.213.240",
"54.195.252.18",
"37.48.92.168",
"211.149.206.17",
"69.55.137.71",
"105.203.253.7",
"188.40.154.61",
"54.197.248.47",
"14.17.79.50",
"213.180.141.14",
"54.69.90.93",
"220.181.150.12",
"180.97.64.39",
"176.126.200.7",
"211.239.114.3",
"206.190.138.5",
"23.15.9.56",
"118.218.136.5",
"130.117.78.73",
"168.144.29.24",
"54.83.20.239",
"64.135.77.80",
"213.47.222.80",
"177.55.109.50",
"8.37.236.4",
"207.244.73.9",
"82.165.111.14",
"187.45.186.80",
"218.38.12.110",
"218.54.30.252",
"37.59.88.105",
"188.165.120.2",
"61.178.146.17",
"174.37.181.31",
"54.231.8.81",
"54.239.34.17",
"23.73.181.50",
"23.62.6.57",
"23.62.6.81",
"23.62.6.88",
"23.62.6.49",
"23.62.6.40",
"23.62.6.51",
"208.111.160.6",
"37.59.93.35",
"5.39.5.229",
"54.230.100.24",
"121.30.192.15",
"163.177.135.4",
"94.31.0.25",
"23.62.6.56",
"149.174.149.6",
"54.230.193.83",
"193.105.99.30",
"188.165.95.82",
"92.222.117.17",
"54.187.10.139",
"107.20.141.16",
"54.225.164.15",
"5.79.80.68",
"54.230.192.9",
"187.17.96.25",
"94.102.52.186",
"121.156.32.12",
"198.245.63.76",
"66.154.48.2",
"37.59.34.142",
"69.16.175.42",
"54.240.235.1",
"104.28.5.25",
"220.181.150.11",
"23.62.6.176",
"77.120.115.18",
"107.20.210.63",
"54.76.77.11",
"93.189.32.153",
"42.121.253.19",
"207.244.73.52",
"103.26.128.84",
"176.32.101.74",
"37.59.198.1",
"54.68.86.96",
"91.220.163.32",
"122.228.251.13",
"173.192.190.27",
"176.32.99.201",
"54.239.36.17",
"54.230.194.68",
"54.230.192.13",
"212.7.200.90",
"184.29.106.13",
"23.62.6.59",
"184.29.106.12",
"23.62.6.58",
"184.29.106.12",
"23.62.6.42",
"23.62.6.80",
"184.29.106.11",
"184.29.106.12",
"179.43.162.25",
"185.36.102.14",
"178.32.161.91",
"198.50.196.24",
"54.230.193.16",
"125.39.78.194",
"92.222.117.17",
"188.165.95.86",
"92.222.117.16",
"188.165.146.7",
"92.222.97.16",
"92.222.117.96",
"92.222.97.7",
"54.187.181.19",
"50.16.205.1",
"54.225.152.23",
"54.68.93.223",
"37.59.88.107",
"37.48.92.169",
"54.243.121.23",
"141.8.192.102",
"188.165.95.92",
"127.0.0.2",
"67.228.38.162",
"109.230.227.2",
"198.154.224.10",
"178.32.5.12",
"212.115.192.18",
"162.159.242.1",
"54.231.14.80",
"176.32.97.226",
"173.254.28.65",
"122.224.9.253",
"81.176.232.17",
"109.73.169.46",
"74.218.88.235",
"176.122.212.3",
"178.18.87.236",
"95.211.81.114",
"188.130.33.51",
"212.7.206.93",
"74.201.34.1",
"178.156.230.11",
"117.79.226.24",
"179.190.48.18",
"174.139.169.22",
"95.169.190.14",
"201.76.59.15",
"104.28.30.37",
"65.49.14.131",
"61.154.102.20",
"142.54.183.16",
"54.231.15.41",
"54.230.193.33",
"74.120.16.151",
"37.59.93.34",
"54.192.192.70",
"74.120.16.154",
"184.51.126.65",
"184.51.126.8",
"184.51.126.56",
"184.51.126.10",
"5.39.5.226",
"54.231.1.129",
"54.230.194.15",
"23.62.6.146",
"23.62.6.96",
"54.208.92.161",
"74.120.16.150",
"54.230.193.31",
"23.62.6.152",
"23.62.7.51",
"184.51.126.9",
"184.51.126.40",
"23.0.160.17",
"23.0.160.27",
"198.50.196.24",
"23.62.6.155",
"23.62.6.130",
"23.62.7.24",
"37.59.93.45",
"23.62.7.139",
"23.62.7.163",
"184.51.126.43",
"184.51.126.58",
"23.62.7.168",
"23.62.7.160",
"23.62.7.147",
"23.62.7.153",
"23.62.7.154",
"23.62.6.123",
"23.62.6.122",
"23.62.6.139",
"23.62.6.137",
"183.136.208.18",
"54.230.195.92",
"23.62.6.90",
"66.198.8.83",
"23.15.8.91",
"54.208.71.111",
"23.62.7.66",
"178.32.238.21",
"23.62.236.26",
"23.15.8.99",
"23.62.6.160",
"23.15.8.232",
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
				printf("read\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
				filepath[size] = '\0';
                                printf("File-%s-\n", filepath);
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
	                                printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				memcpy(filepath, dummy, 256);
				break;
			case 1:
				printf("write\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
				filepath[size] = '\0';
				printf("File-%s-\n", filepath);
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
	                                printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				memcpy(filepath, dummy, 256);
				break;
			case 45:
				printf("recvfrom\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				printf("Inode - %d\n",inode);
				
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
					printf("eval present pppp\n");
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
						printf("number_count- %d",number_count);
						if( number_count > 1000)
						{
							//obfuscated js present ( numbers with parsint() or String.fromCharCode()
							system("zenity --error --text=malicious_webpage_detected_do_not_proceed_or_download");
							printf("numbers and parseInt or String.fromCharCode present pppp\n");
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
                                	printf("Message-%s-\n\n", message);
				}
				memcpy(message, dummy, 1024);
				break;
			case 47:
				printf("recvmsg\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				printf("Inode - %d\n",inode);
				break;
			case 44:
				printf("sendto\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("File-%s-\n", filepath);
				i = 8;
				j = 0;
			        while(filepath[i] != ']')
			        {
			                char_temp[j++] = filepath[i++];
					char_temp[j] = '\0';
			        }
				memcpy(filepath, dummy, 256);
			        inode = atoi(char_temp);
				printf("Inode - %d\n",inode);

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
                                printf("Message-%s-\n\n", message);
				memcpy(message, dummy, 1024);
				break;
			case 46:
				printf("sendmsg\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 41:
				printf("socket\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 42:
				printf("connect\n");
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
				printf("Connect To IP-%s-\n",ip_addr);
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
				printf("bind\n");
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
                                printf("Sockfd %llu binds to IP %s-\n\n", regs.rdi, ip_addr);
				break;
			case 2:
				printf("open\n");
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
                                printf("FIlepath -%s-\n\n", message);
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
				printf("close\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("Filepath -%s-\n\n", filepath);
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
				printf("fstat\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("On File -%s-\n\n", filepath);
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
				printf("lseek\n");
				//printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				sprintf(fdpath,"/proc/%u/fd/%llu",proc,regs.rdi);
                                size = readlink(fdpath, filepath, 256);
                                filepath[size] = '\0';
                                printf("On File -%s-\n\n", filepath);
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
				printf("mmap\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 11:
				printf("munmap\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 12:
				printf("brk\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 202:

				printf("futex\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
                                temp_long = ptrace(PTRACE_PEEKDATA, proc, regs.rdi , NULL);
				printf("-%lu-\n\n",temp_long);
				break;
			case 22:
				printf("pipe\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
			case 59:
				printf("execve\n");
				printf("%llu - %llu - %llu - %llu - %llu - %llu\n", regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				break;
		}
         	ptrace(PTRACE_SYSCALL,proc, NULL, NULL);
	}
	return 0;
}
