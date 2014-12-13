#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main()
{
        char* fdpath = "/proc/3541/fd/14";
        char* tcp_path = "/proc/3541/net/tcp";
        char* udp_path = "/proc/3541/net/udp";

        char* filepath = malloc(1024);
        char* char_temp = malloc(64);
        char* line = malloc(1024);
	char* command = malloc(1024);
	char* ip_addr = malloc(64);

        int inode = 0, size, i, j, flag = 1;

        size = readlink(fdpath, filepath, 1024);
        filepath[size] = '\0';
        printf("File-%s-\n", filepath);

        i = 8;
        j = 0;
        while(filepath[i] != ']')
        {
                char_temp[j++] = filepath[i++];
        }
        inode = atoi(char_temp);

        printf("\n%d\n",inode);
	sprintf(command, "grep -a %d %s", inode, tcp_path);

	FILE* fp=popen(command, "r");
	fgets(line, 1024, fp);
	printf("%s\n",line);

        i = 20;
        j = 0;
        while(line[i] != ':')
        {
                char_temp[j] = line[i];
                i++;
                j++;
        }
        printf("%s\n",char_temp);
	
	unsigned int a, b, c, d;

	if (sscanf(char_temp, "%2x%2x%2x%2x", &a, &b, &c, &d) != 4)
        	return -1;

	snprintf(ip_addr, 64, "%u.%u.%u.%u", a, b, c, d);
	printf("%s\n",ip_addr);
}
