#include <stdio.h>
#include <string.h>

//#define BULK_TEST

#ifndef BULK_TEST
char sysenter_match[] = "syscalls:sys_enter_sendmsg:";
char sysexit_match[]  = "syscalls:sys_exit_sendmsg:";
#else
char sysenter_match[] = "syscalls:sys_enter_sendto:";
char sysexit_match[]  = "syscalls:sys_exit_sendto:";
#endif
char proenter_match[] = "probe:nf_hook_slow:";
char proexit_match[]  = "probe:nf_hook_slow_1:";

int main(int argc, char *argv[])
{
	char event[500];
	double tstamp_sysenter;
	double tstamp_sysexit;
	double tstamp_nfenter;
	double tstamp_nfexit;
	double in_stamp;
	double sys_times = 0.0;
	double pro_times = 0.0;
	int stack = 0;
	char flag = 0;

	do
	{
		scanf("%s%s%s%lf%s%s", event, event, event, &in_stamp, event, event);
		if(strcmp(event, sysenter_match) == 0)
		{
			flag = 1;
			tstamp_sysenter = in_stamp;
		}
		else if(strcmp(event, sysexit_match) == 0)
		{
			flag = 0;
			tstamp_sysexit = in_stamp;
			sys_times += (tstamp_sysexit - tstamp_sysenter);
		}

		if(flag == 1)
		{
			if(strcmp(event, proenter_match) == 0)
			{
				if(stack == 0)
					tstamp_nfenter = in_stamp;
				stack++;
			}
			else if(strcmp(event, proexit_match) == 0)
			{
				stack--;
				if(stack == 0)
				{
					tstamp_nfexit = in_stamp;
					pro_times += (tstamp_nfexit - tstamp_nfenter);
				}
			}
		}
	}
	while(gets(event) != NULL);

	printf("%lf %lf\n", pro_times, sys_times);

	return 0;
}



