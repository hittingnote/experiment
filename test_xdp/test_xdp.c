#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_api.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

#define u32         unsigned int
#define u16         unsigned short
#define u64         unsigned long long


SEC("test_xdp") int test_xdp_main(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    u64 nh_off;
    u16 h_proto;
    u32 src_ip;
    u32 dst_ip;
//    u32 ip_addr;

    nh_off = sizeof(struct ethhdr);
    if(data + nh_off > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;
    if(h_proto != htons(ETH_P_IP))
    {
        printt("Not IP packets. passed!\n");
        return XDP_PASS;
    }

    struct iphdr *iph = data + nh_off;
    if(iph+1 > data_end)
        return XDP_DROP;

    src_ip = ntohl(iph->saddr);
    dst_ip = ntohl(iph->daddr);
//    ip_addr = iph->saddr;
    printt("src = 0x%x, dst = 0x%x\n", src_ip, dst_ip);
    //printt("src = %u.%u.%u.%u, ", ip_addr%256, (ip_addr=ip_addr/256)%256, (ip_addr=ip_addr/256)%256, (ip_addr=ip_addr/256)%256);
/*
   src_ip = iph->saddr;
   dst_ip = iph->daddr;

    printt("src = %u.%u.%u.%u, ", src_ip%256, (src_ip=src_ip/256)%256, (src_ip=src_ip/256)%256, (src_ip=src_ip/256)%256);
    printt("dst = %u.%u.%u.%u\n", dst_ip%256, (dst_ip=dst_ip/256)%256, (dst_ip=dst_ip/256)%256, (dst_ip=dst_ip/256)%256);
*/
    return XDP_PASS;
}


char license[] SEC("license") = "GPL";


