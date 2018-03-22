#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp_drop") int drop_main(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char license[] SEC("license") = "GPL";



