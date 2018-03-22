#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

using namespace std;



int main(int argc, char *argv[])
{
//    srand((unsigned) time(NULL));
/*
    unsigned int src_ip = rand();
    printf("ip = %u.%u.%u.%u\n",
            src_ip%256,
            (src_ip=src_ip/256)%256,
            (src_ip=src_ip/256)%256,
            (src_ip=src_ip/256)%256);
*/
    if(strcmp(argv[1], "add") == 0)
    {
        srand((unsigned) time(NULL));
        int loop_t = 0;

        int str_len = strlen(argv[2]);
        for(int i = 0; i < str_len; i++)
        {
            loop_t = 10*loop_t + (argv[2][i]-'0');
        }

        for(int i = 0; i < loop_t; i++)
        {
            unsigned int src_ip = rand();
            char cmd[1000];
            sprintf(cmd, "iptables -I FORWARD -s %u.%u.%u.%u -j DROP",
                    src_ip%256,
                    (src_ip/256)%256,
                    (src_ip/256)%256,
                    (src_ip/256)%256);
            system(cmd);
        }
    }
    else if(strcmp(argv[1], "del") == 0)
    {
        int loop_t = 0;
        int str_len = strlen(argv[2]);
        for(int i = 0; i < str_len; i++)
            loop_t = 10*loop_t + (argv[2][i]-'0');

        for(int i = 0; i < loop_t; i++)
            system("iptables -D FORWARD 1");
    }

    return 0;
}



