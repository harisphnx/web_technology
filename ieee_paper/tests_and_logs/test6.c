#include<stdio.h>

int main()
{
	char* temp = "hello";
	char * temp2;
	unsigned long long f;
	
	f = temp;
	printf("%llu\n",f);
	temp2 = 26892512;
	//snprintf(temp2,1024,"%p",f);
        printf("-%s-\n", temp2);


}
