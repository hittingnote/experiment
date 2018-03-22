#include "bpf_api.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

__section("bpf") int bpf_main(struct __sk_buff *skb)
{
    return TC_ACT_SHOT;
}


char license[] __section("license") = "GPL";



