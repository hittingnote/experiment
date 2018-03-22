#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>

using namespace std;


int main(int argc, char *argv[])
{
    srand((unsigned) time(NULL));

    printf("#include <linux/bpf.h>\n");
    printf("#include \"bpf_helpers.h\"\n");
    printf("#include \"bpf_api.h\"\n");
    printf("#include <linux/if_ether.h>\n");
    printf("#include <linux/ip.h>\n\n");
    printf("#define u32\t\tunsigned int\n");
    printf("#define u16\t\tunsigned short\n");
    printf("#define u64\t\tunsigned long long\n\n");

    printf("SEC(\"xdp\") int xdp_main(struct xdp_md *ctx)\n{\n");
    printf("\tvoid *data_end = (void*)(long)ctx->data_end;\n");
    printf("\tvoid *data = (void*)(long)ctx->data;\n");
    printf("\tstruct ethhdr *eth = data;\n");
    printf("\tu64 nh_off;\n");
    printf("\tu16 h_proto;\n");
    printf("\tu32 src_ip;\n");
    printf("\tint ret = XDP_PASS;\n\n");

    printf("\tnh_off = sizeof(struct ethhdr);\n");
    printf("\tif(data + nh_off > data_end)\n");
    printf("\t\treturn XDP_DROP;\n\n");
    printf("\th_proto = eth->h_proto;\n");
    printf("\tif(h_proto != htons(ETH_P_IP))\n");
    printf("\t\treturn XDP_PASS;\n\n");

    printf("\tstruct iphdr *iph = data + nh_off;\n");
    printf("\tif(iph+1 > data_end)\n");
    printf("\t\treturn XDP_DROP;\n\n");

    printf("\tsrc_ip = ntohl(iph->saddr);\n");

    int loop_t = 0;
    int str_len = strlen(argv[1]);
    for(int i = 0; i < str_len; i++)
        loop_t = loop_t*10 + (argv[1][i]-'0');

    for(int i = 0; i < loop_t; i++)
    {
        unsigned int match_ip = rand();
        printf("\t%sif(src_ip == 0x%x)\n", (i==0)?"":"else ", match_ip);
        printf("\t\tret =  XDP_DROP;\n");
    }

    printf("\n\treturn ret;\n}\n\n");
    printf("char license[] SEC(\"license\") = \"GPL\";\n\n");

    return 0;
}



