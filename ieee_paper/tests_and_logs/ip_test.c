#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main()
{
	char* fdpath = "/proc/5306/fd/13";
	char* tcp_path = "/proc/5306/net/tcp";
	char* udp_path = "/proc/5306/net/udp";

	FILE* tcp = fopen(tcp_path, "r");
	FILE* udp = fopen(udp_path, "r");

	char* filepath = malloc(1024);
	char* char_temp = malloc(64);
	char* line = malloc(1024);
	
	int inode = 0, size, i, j, flag = 1;


	size = readlink(fdpath, filepath, 1024);
	filepath[size] = '\0';
        printf("File-%s-\n", filepath);

	i = 8;
	j = 0;
	while(filepath[i] != ']')
	{
		char_temp[j] = filepath[i];
		i++;
		j++;
	}
	inode = atoi(char_temp);
	
	printf("\n%d\n",inode);
	
	while( flag == 1 && fgets(line, 1024, tcp))
	{
		i = 91;
		j = 0;
		flag = 0;
		while( line[i] != ' ' )
		{
			if( line[i] != char_temp[j] )
			{
				flag = 1;
				break;
			}
			i++;
			j++;
		}
	}
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
	
}












