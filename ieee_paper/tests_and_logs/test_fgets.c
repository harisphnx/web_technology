#include<stdio.h>
#include<stdlib.h>
#include<string.h>


int main()
{
	char line[15];
	FILE* fp = fopen("ipblacklist.txt","r");
	FILE* fr = fopen("sorted.txt", "wr");
	int i, x;	

	while(i < 15)
        {
                line[i++] = '\0';
        }
	fprintf(fr,"blacklisted_ip = { \"");
	while( fgets(line, 15, fp) != NULL)
	{
		//printf("%s",line);
		i = 0;
		x = strlen(line);
		while(i < (x-1))
		{
			fputc(line[i++],fr);
		}
		i = 0;
		while(i < 15)
                {
                        line[i++] = '\0';
                }

		//fprintf(fr,line);
		fprintf(fr,"\",\n\"");
	}


}
