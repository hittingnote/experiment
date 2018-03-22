#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>

using namespace std;


int main(int argc, char *argv[])
{
    srand((unsigned) time(NULL));

    printf("#include \"bpf_api.h\"\n");
    printf("#include <linux/if_ether.h>\n");
    printf("#include <linux/ip.h>\n\n");

    printf("__section(\"bpf\") int bpf_main(struct __sk_buff *skb)\n");
    printf("{\n");
    printf("\tuint32_t src_ip;\n");
    printf("\tint nh_off = BPF_LL_OFF + ETH_HLEN;\n");
    printf("\tint ret = TC_ACT_OK;\n\n");

    printf("\tsrc_ip = load_word(skb, nh_off+offsetof(struct iphdr, saddr));\n");

    int loop_t = 0;
    int str_len = strlen(argv[1]);
    for(int i = 0; i < str_len; i++)
        loop_t = loop_t*10 + (argv[1][i]-'0');

    for(int i = 0; i < loop_t; i++)
    {
        unsigned int match_ip = rand();
        printf("\t%sif(src_ip == 0x%x)\n", (i==0)?"":"else ", match_ip);
        printf("\t\tret = TC_ACT_SHOT;\n");
    }

    printf("\treturn ret;\n}\n\n");
    printf("char license[] __section(\"license\") = \"GPL\";\n\n");

    return 0;
}



