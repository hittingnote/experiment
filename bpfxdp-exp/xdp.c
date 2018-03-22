#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_api.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

#define u32		unsigned int
#define u16		unsigned short
#define u64		unsigned long long

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 nh_off;
	u16 h_proto;
	u32 src_ip;
	int ret = XDP_PASS;

	nh_off = sizeof(struct ethhdr);
	if(data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;
	if(h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = data + nh_off;
	if(iph+1 > data_end)
		return XDP_DROP;

	src_ip = ntohl(iph->saddr);
	if(src_ip == 0x7785dc34)
		ret =  XDP_DROP;
	else if(src_ip == 0x4b35f7e7)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c3db6d8)
		ret =  XDP_DROP;
	else if(src_ip == 0x31b4ee01)
		ret =  XDP_DROP;
	else if(src_ip == 0x39162d7a)
		ret =  XDP_DROP;
	else if(src_ip == 0x81c46ec)
		ret =  XDP_DROP;
	else if(src_ip == 0x130c786)
		ret =  XDP_DROP;
	else if(src_ip == 0x1fa85f50)
		ret =  XDP_DROP;
	else if(src_ip == 0x6ddd047e)
		ret =  XDP_DROP;
	else if(src_ip == 0x3945ae06)
		ret =  XDP_DROP;
	else if(src_ip == 0x7dde1f5d)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e3d3246)
		ret =  XDP_DROP;
	else if(src_ip == 0x423a44b)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d273846)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ef2e583)
		ret =  XDP_DROP;
	else if(src_ip == 0x268a73e3)
		ret =  XDP_DROP;
	else if(src_ip == 0xffbbdf4)
		ret =  XDP_DROP;
	else if(src_ip == 0x4d0ba992)
		ret =  XDP_DROP;
	else if(src_ip == 0x25745e39)
		ret =  XDP_DROP;
	else if(src_ip == 0x2efb9c71)
		ret =  XDP_DROP;
	else if(src_ip == 0x2ce8dfa9)
		ret =  XDP_DROP;
	else if(src_ip == 0x5a678994)
		ret =  XDP_DROP;
	else if(src_ip == 0x7c6b4881)
		ret =  XDP_DROP;
	else if(src_ip == 0x4c64da57)
		ret =  XDP_DROP;
	else if(src_ip == 0x229a276d)
		ret =  XDP_DROP;
	else if(src_ip == 0x109fa477)
		ret =  XDP_DROP;
	else if(src_ip == 0x3cb8fff3)
		ret =  XDP_DROP;
	else if(src_ip == 0x3666ff7a)
		ret =  XDP_DROP;
	else if(src_ip == 0x2ef255e4)
		ret =  XDP_DROP;
	else if(src_ip == 0x594ee0b6)
		ret =  XDP_DROP;
	else if(src_ip == 0x32d16374)
		ret =  XDP_DROP;
	else if(src_ip == 0x26783218)
		ret =  XDP_DROP;
	else if(src_ip == 0x2484d89d)
		ret =  XDP_DROP;
	else if(src_ip == 0xf0f1a4d)
		ret =  XDP_DROP;
	else if(src_ip == 0x582d2019)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d9b0617)
		ret =  XDP_DROP;
	else if(src_ip == 0x172b6139)
		ret =  XDP_DROP;
	else if(src_ip == 0x595de7a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x7d436567)
		ret =  XDP_DROP;
	else if(src_ip == 0x50865b7)
		ret =  XDP_DROP;
	else if(src_ip == 0x12a395a6)
		ret =  XDP_DROP;
	else if(src_ip == 0x7b2184c4)
		ret =  XDP_DROP;
	else if(src_ip == 0x634597fd)
		ret =  XDP_DROP;
	else if(src_ip == 0x16c739f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x1848bd0a)
		ret =  XDP_DROP;
	else if(src_ip == 0x22387d81)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d51add4)
		ret =  XDP_DROP;
	else if(src_ip == 0x28447aff)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f442713)
		ret =  XDP_DROP;
	else if(src_ip == 0x62c60c0e)
		ret =  XDP_DROP;
	else if(src_ip == 0x57401770)
		ret =  XDP_DROP;
	else if(src_ip == 0x1c2d06bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d2d95a2)
		ret =  XDP_DROP;
	else if(src_ip == 0x53ab5ff1)
		ret =  XDP_DROP;
	else if(src_ip == 0x6891e113)
		ret =  XDP_DROP;
	else if(src_ip == 0x5fc7bd0f)
		ret =  XDP_DROP;
	else if(src_ip == 0x644b0468)
		ret =  XDP_DROP;
	else if(src_ip == 0x254ae106)
		ret =  XDP_DROP;
	else if(src_ip == 0x162ebc8a)
		ret =  XDP_DROP;
	else if(src_ip == 0x133d5a4c)
		ret =  XDP_DROP;
	else if(src_ip == 0x7e99c1bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x49001ffe)
		ret =  XDP_DROP;
	else if(src_ip == 0x39b58c65)
		ret =  XDP_DROP;
	else if(src_ip == 0x231e9a5a)
		ret =  XDP_DROP;
	else if(src_ip == 0x580f3a4b)
		ret =  XDP_DROP;
	else if(src_ip == 0x11e2ac7e)
		ret =  XDP_DROP;
	else if(src_ip == 0xb9a071)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f3a9b85)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b40941e)
		ret =  XDP_DROP;
	else if(src_ip == 0x7dfd05d9)
		ret =  XDP_DROP;
	else if(src_ip == 0x7443013c)
		ret =  XDP_DROP;
	else if(src_ip == 0x7de429c4)
		ret =  XDP_DROP;
	else if(src_ip == 0x791e8a9d)
		ret =  XDP_DROP;
	else if(src_ip == 0x5788993a)
		ret =  XDP_DROP;
	else if(src_ip == 0x14ab63b6)
		ret =  XDP_DROP;
	else if(src_ip == 0x116747a8)
		ret =  XDP_DROP;
	else if(src_ip == 0x79c116bb)
		ret =  XDP_DROP;
	else if(src_ip == 0x51fd118a)
		ret =  XDP_DROP;
	else if(src_ip == 0x39abc2a7)
		ret =  XDP_DROP;
	else if(src_ip == 0x69053dce)
		ret =  XDP_DROP;
	else if(src_ip == 0x34c31d98)
		ret =  XDP_DROP;
	else if(src_ip == 0x10ebda17)
		ret =  XDP_DROP;
	else if(src_ip == 0x532448a)
		ret =  XDP_DROP;
	else if(src_ip == 0x71f0b33a)
		ret =  XDP_DROP;
	else if(src_ip == 0x64973a08)
		ret =  XDP_DROP;
	else if(src_ip == 0x6dc4259d)
		ret =  XDP_DROP;
	else if(src_ip == 0x51b8704a)
		ret =  XDP_DROP;
	else if(src_ip == 0x48e23e70)
		ret =  XDP_DROP;
	else if(src_ip == 0x130f06a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x67e72cd4)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c1f98bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x11a8c860)
		ret =  XDP_DROP;
	else if(src_ip == 0x30e74cd2)
		ret =  XDP_DROP;
	else if(src_ip == 0x15d52521)
		ret =  XDP_DROP;
	else if(src_ip == 0x34c762ba)
		ret =  XDP_DROP;
	else if(src_ip == 0x8f6871e)
		ret =  XDP_DROP;
	else if(src_ip == 0x27b7d1a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3581032b)
		ret =  XDP_DROP;
	else if(src_ip == 0x783122a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x12f865be)
		ret =  XDP_DROP;
	else if(src_ip == 0x337e0904)
		ret =  XDP_DROP;
	else if(src_ip == 0x6c7423df)
		ret =  XDP_DROP;
	else if(src_ip == 0x10dc8f83)
		ret =  XDP_DROP;
	else if(src_ip == 0x2c9c93a2)
		ret =  XDP_DROP;
	else if(src_ip == 0x43fcbd19)
		ret =  XDP_DROP;
	else if(src_ip == 0x2587f339)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e03db4a)
		ret =  XDP_DROP;
	else if(src_ip == 0x3dbdd3d4)
		ret =  XDP_DROP;
	else if(src_ip == 0x778504c3)
		ret =  XDP_DROP;
	else if(src_ip == 0x77af9df1)
		ret =  XDP_DROP;
	else if(src_ip == 0x26c311a2)
		ret =  XDP_DROP;
	else if(src_ip == 0x2c48225c)
		ret =  XDP_DROP;
	else if(src_ip == 0x89b7808)
		ret =  XDP_DROP;
	else if(src_ip == 0x2bf5562c)
		ret =  XDP_DROP;
	else if(src_ip == 0x1e38d596)
		ret =  XDP_DROP;
	else if(src_ip == 0x6d32b210)
		ret =  XDP_DROP;
	else if(src_ip == 0x19b97bc9)
		ret =  XDP_DROP;
	else if(src_ip == 0x6ff145e0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3614f080)
		ret =  XDP_DROP;
	else if(src_ip == 0x2cc8826d)
		ret =  XDP_DROP;
	else if(src_ip == 0x57d872b4)
		ret =  XDP_DROP;
	else if(src_ip == 0x1234893c)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e714acd)
		ret =  XDP_DROP;
	else if(src_ip == 0x8bfbf87)
		ret =  XDP_DROP;
	else if(src_ip == 0x2809ae5e)
		ret =  XDP_DROP;
	else if(src_ip == 0x7338ad87)
		ret =  XDP_DROP;
	else if(src_ip == 0x11b646a5)
		ret =  XDP_DROP;
	else if(src_ip == 0x4fc17ffe)
		ret =  XDP_DROP;
	else if(src_ip == 0x28b9b0b2)
		ret =  XDP_DROP;
	else if(src_ip == 0x9e76948)
		ret =  XDP_DROP;
	else if(src_ip == 0x62b9e5bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c37b9b7)
		ret =  XDP_DROP;
	else if(src_ip == 0x765b8d27)
		ret =  XDP_DROP;
	else if(src_ip == 0x7396753f)
		ret =  XDP_DROP;
	else if(src_ip == 0x8d44d59)
		ret =  XDP_DROP;
	else if(src_ip == 0x3a584a41)
		ret =  XDP_DROP;
	else if(src_ip == 0x191e6878)
		ret =  XDP_DROP;
	else if(src_ip == 0x46d828a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x78161e15)
		ret =  XDP_DROP;
	else if(src_ip == 0x10a36d3c)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e87c694)
		ret =  XDP_DROP;
	else if(src_ip == 0x1ed92fb8)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ceb8f98)
		ret =  XDP_DROP;
	else if(src_ip == 0x47233e9c)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ace85e4)
		ret =  XDP_DROP;
	else if(src_ip == 0x5b24652e)
		ret =  XDP_DROP;
	else if(src_ip == 0x3455f0ac)
		ret =  XDP_DROP;
	else if(src_ip == 0x648801ae)
		ret =  XDP_DROP;
	else if(src_ip == 0x4b15ab0f)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a6ae12c)
		ret =  XDP_DROP;
	else if(src_ip == 0x1150841b)
		ret =  XDP_DROP;
	else if(src_ip == 0x22ee1dc3)
		ret =  XDP_DROP;
	else if(src_ip == 0x7c9f6a68)
		ret =  XDP_DROP;
	else if(src_ip == 0x4fc1cee8)
		ret =  XDP_DROP;
	else if(src_ip == 0x2baddd4a)
		ret =  XDP_DROP;
	else if(src_ip == 0x24a918c6)
		ret =  XDP_DROP;
	else if(src_ip == 0x42fa7c6f)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d6423ef)
		ret =  XDP_DROP;
	else if(src_ip == 0x746a98c4)
		ret =  XDP_DROP;
	else if(src_ip == 0x6bb42d21)
		ret =  XDP_DROP;
	else if(src_ip == 0x474b8d37)
		ret =  XDP_DROP;
	else if(src_ip == 0x57247e81)
		ret =  XDP_DROP;
	else if(src_ip == 0x47ebe6d8)
		ret =  XDP_DROP;
	else if(src_ip == 0x3da71a5f)
		ret =  XDP_DROP;
	else if(src_ip == 0x4abaf3c0)
		ret =  XDP_DROP;
	else if(src_ip == 0x50c03431)
		ret =  XDP_DROP;
	else if(src_ip == 0x77ff64a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x63d95c39)
		ret =  XDP_DROP;
	else if(src_ip == 0x17985cd4)
		ret =  XDP_DROP;
	else if(src_ip == 0x701582b5)
		ret =  XDP_DROP;
	else if(src_ip == 0x747cc975)
		ret =  XDP_DROP;
	else if(src_ip == 0x56202368)
		ret =  XDP_DROP;
	else if(src_ip == 0xeeeb26d)
		ret =  XDP_DROP;
	else if(src_ip == 0x3168590d)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d436204)
		ret =  XDP_DROP;
	else if(src_ip == 0x59bd3852)
		ret =  XDP_DROP;
	else if(src_ip == 0xc8cbe3b)
		ret =  XDP_DROP;
	else if(src_ip == 0x519952b0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e453a00)
		ret =  XDP_DROP;
	else if(src_ip == 0x57a2694a)
		ret =  XDP_DROP;
	else if(src_ip == 0x3c0433dc)
		ret =  XDP_DROP;
	else if(src_ip == 0x4f95be1b)
		ret =  XDP_DROP;
	else if(src_ip == 0x7a90870e)
		ret =  XDP_DROP;
	else if(src_ip == 0x38a39e45)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f578d03)
		ret =  XDP_DROP;
	else if(src_ip == 0x263e6458)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d4cb70b)
		ret =  XDP_DROP;
	else if(src_ip == 0x62520972)
		ret =  XDP_DROP;
	else if(src_ip == 0x63a28848)
		ret =  XDP_DROP;
	else if(src_ip == 0x51b74fd0)
		ret =  XDP_DROP;
	else if(src_ip == 0x4e063693)
		ret =  XDP_DROP;
	else if(src_ip == 0x2aee157f)
		ret =  XDP_DROP;
	else if(src_ip == 0x28dbce51)
		ret =  XDP_DROP;
	else if(src_ip == 0x15f21d6c)
		ret =  XDP_DROP;
	else if(src_ip == 0x68952fde)
		ret =  XDP_DROP;
	else if(src_ip == 0x7396c211)
		ret =  XDP_DROP;
	else if(src_ip == 0x66b2519d)
		ret =  XDP_DROP;
	else if(src_ip == 0x6094947e)
		ret =  XDP_DROP;
	else if(src_ip == 0x57701e4a)
		ret =  XDP_DROP;
	else if(src_ip == 0x7e4aae72)
		ret =  XDP_DROP;
	else if(src_ip == 0x50aa1734)
		ret =  XDP_DROP;
	else if(src_ip == 0x4bece7bf)
		ret =  XDP_DROP;
	else if(src_ip == 0x546ad1da)
		ret =  XDP_DROP;
	else if(src_ip == 0x5f98c9a1)
		ret =  XDP_DROP;
	else if(src_ip == 0x7d5540cc)
		ret =  XDP_DROP;
	else if(src_ip == 0x71ae33df)
		ret =  XDP_DROP;
	else if(src_ip == 0x395601f3)
		ret =  XDP_DROP;
	else if(src_ip == 0x9e1ff08)
		ret =  XDP_DROP;
	else if(src_ip == 0x4347868f)
		ret =  XDP_DROP;
	else if(src_ip == 0x779b3bf3)
		ret =  XDP_DROP;
	else if(src_ip == 0x61846852)
		ret =  XDP_DROP;
	else if(src_ip == 0x7f4bba6c)
		ret =  XDP_DROP;
	else if(src_ip == 0x4730fa0e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c14ef60)
		ret =  XDP_DROP;
	else if(src_ip == 0x37ef58b1)
		ret =  XDP_DROP;
	else if(src_ip == 0x66888711)
		ret =  XDP_DROP;
	else if(src_ip == 0x25353b9)
		ret =  XDP_DROP;
	else if(src_ip == 0x153c0fbc)
		ret =  XDP_DROP;
	else if(src_ip == 0x48da9083)
		ret =  XDP_DROP;
	else if(src_ip == 0x65f5dc01)
		ret =  XDP_DROP;
	else if(src_ip == 0x66f35f8c)
		ret =  XDP_DROP;
	else if(src_ip == 0x16e0c717)
		ret =  XDP_DROP;
	else if(src_ip == 0x10e3f180)
		ret =  XDP_DROP;
	else if(src_ip == 0xfcf2ddd)
		ret =  XDP_DROP;
	else if(src_ip == 0x2cd2e483)
		ret =  XDP_DROP;
	else if(src_ip == 0x7979215f)
		ret =  XDP_DROP;
	else if(src_ip == 0x365efef)
		ret =  XDP_DROP;
	else if(src_ip == 0x13853620)
		ret =  XDP_DROP;
	else if(src_ip == 0x5a0db5dd)
		ret =  XDP_DROP;
	else if(src_ip == 0x5ad60e39)
		ret =  XDP_DROP;
	else if(src_ip == 0x11cfe492)
		ret =  XDP_DROP;
	else if(src_ip == 0x2ab7cd11)
		ret =  XDP_DROP;
	else if(src_ip == 0x26c2f5f9)
		ret =  XDP_DROP;
	else if(src_ip == 0x663ab66d)
		ret =  XDP_DROP;
	else if(src_ip == 0xa5096b3)
		ret =  XDP_DROP;
	else if(src_ip == 0x241836c5)
		ret =  XDP_DROP;
	else if(src_ip == 0x57e8ea4c)
		ret =  XDP_DROP;
	else if(src_ip == 0x43a698a6)
		ret =  XDP_DROP;
	else if(src_ip == 0x2dfa35cd)
		ret =  XDP_DROP;
	else if(src_ip == 0x1b3070db)
		ret =  XDP_DROP;
	else if(src_ip == 0x3b41d49a)
		ret =  XDP_DROP;
	else if(src_ip == 0xf7e9e20)
		ret =  XDP_DROP;
	else if(src_ip == 0x1a7c2b47)
		ret =  XDP_DROP;
	else if(src_ip == 0x272cea8)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b938d80)
		ret =  XDP_DROP;
	else if(src_ip == 0x526b83f8)
		ret =  XDP_DROP;
	else if(src_ip == 0x68fb55ba)
		ret =  XDP_DROP;
	else if(src_ip == 0x6de6e139)
		ret =  XDP_DROP;
	else if(src_ip == 0x67a793b5)
		ret =  XDP_DROP;
	else if(src_ip == 0x31d5e63d)
		ret =  XDP_DROP;
	else if(src_ip == 0x53dcbd3a)
		ret =  XDP_DROP;
	else if(src_ip == 0x4e9af341)
		ret =  XDP_DROP;
	else if(src_ip == 0x48b6ad54)
		ret =  XDP_DROP;
	else if(src_ip == 0x64c0aebb)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e6a211f)
		ret =  XDP_DROP;
	else if(src_ip == 0x758991d7)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e39d01a)
		ret =  XDP_DROP;
	else if(src_ip == 0x61d0110e)
		ret =  XDP_DROP;
	else if(src_ip == 0x90ec7f8)
		ret =  XDP_DROP;
	else if(src_ip == 0x384785f7)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ca61f47)
		ret =  XDP_DROP;
	else if(src_ip == 0x1adeac8a)
		ret =  XDP_DROP;
	else if(src_ip == 0x62ff5309)
		ret =  XDP_DROP;
	else if(src_ip == 0x63691540)
		ret =  XDP_DROP;
	else if(src_ip == 0x11962f7)
		ret =  XDP_DROP;
	else if(src_ip == 0x6d4fe9bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x7814c06)
		ret =  XDP_DROP;
	else if(src_ip == 0x59024d43)
		ret =  XDP_DROP;
	else if(src_ip == 0x30f68262)
		ret =  XDP_DROP;
	else if(src_ip == 0x357b81d3)
		ret =  XDP_DROP;
	else if(src_ip == 0x7432be1f)
		ret =  XDP_DROP;
	else if(src_ip == 0x6c3856fc)
		ret =  XDP_DROP;
	else if(src_ip == 0x44fa1ff3)
		ret =  XDP_DROP;
	else if(src_ip == 0xeaee966)
		ret =  XDP_DROP;
	else if(src_ip == 0x6eab25a5)
		ret =  XDP_DROP;
	else if(src_ip == 0x308dad74)
		ret =  XDP_DROP;
	else if(src_ip == 0x611a6d5f)
		ret =  XDP_DROP;
	else if(src_ip == 0x57a67b5f)
		ret =  XDP_DROP;
	else if(src_ip == 0x1e748ead)
		ret =  XDP_DROP;
	else if(src_ip == 0x48c20114)
		ret =  XDP_DROP;
	else if(src_ip == 0x97c619c)
		ret =  XDP_DROP;
	else if(src_ip == 0x72514be8)
		ret =  XDP_DROP;
	else if(src_ip == 0x175cf455)
		ret =  XDP_DROP;
	else if(src_ip == 0x52330ef1)
		ret =  XDP_DROP;
	else if(src_ip == 0x5711faa3)
		ret =  XDP_DROP;
	else if(src_ip == 0x75c71574)
		ret =  XDP_DROP;
	else if(src_ip == 0x47bca0c8)
		ret =  XDP_DROP;
	else if(src_ip == 0x354bcabd)
		ret =  XDP_DROP;
	else if(src_ip == 0x57972682)
		ret =  XDP_DROP;
	else if(src_ip == 0x50cb68c0)
		ret =  XDP_DROP;
	else if(src_ip == 0x6d9350b4)
		ret =  XDP_DROP;
	else if(src_ip == 0x143d45ca)
		ret =  XDP_DROP;
	else if(src_ip == 0x6baa154b)
		ret =  XDP_DROP;
	else if(src_ip == 0x5092a3bd)
		ret =  XDP_DROP;
	else if(src_ip == 0x77a65b0a)
		ret =  XDP_DROP;
	else if(src_ip == 0x6cc37842)
		ret =  XDP_DROP;
	else if(src_ip == 0x3de28d79)
		ret =  XDP_DROP;
	else if(src_ip == 0x7f27a710)
		ret =  XDP_DROP;
	else if(src_ip == 0x45c5c586)
		ret =  XDP_DROP;
	else if(src_ip == 0x6ed90fdc)
		ret =  XDP_DROP;
	else if(src_ip == 0x34a328e4)
		ret =  XDP_DROP;
	else if(src_ip == 0x39f883a5)
		ret =  XDP_DROP;
	else if(src_ip == 0x5b1166d8)
		ret =  XDP_DROP;
	else if(src_ip == 0x799d48d7)
		ret =  XDP_DROP;
	else if(src_ip == 0x48a76d0b)
		ret =  XDP_DROP;
	else if(src_ip == 0x49bc8c7d)
		ret =  XDP_DROP;
	else if(src_ip == 0x2a2af64b)
		ret =  XDP_DROP;
	else if(src_ip == 0x29c1da6a)
		ret =  XDP_DROP;
	else if(src_ip == 0x216307dc)
		ret =  XDP_DROP;
	else if(src_ip == 0x489f84f9)
		ret =  XDP_DROP;
	else if(src_ip == 0x7283db7e)
		ret =  XDP_DROP;
	else if(src_ip == 0x2adf6979)
		ret =  XDP_DROP;
	else if(src_ip == 0x3af0d0e1)
		ret =  XDP_DROP;
	else if(src_ip == 0x9e0cfd4)
		ret =  XDP_DROP;
	else if(src_ip == 0x7d12786a)
		ret =  XDP_DROP;
	else if(src_ip == 0x1202cb84)
		ret =  XDP_DROP;
	else if(src_ip == 0x7fa7e548)
		ret =  XDP_DROP;
	else if(src_ip == 0x44cf1932)
		ret =  XDP_DROP;
	else if(src_ip == 0x474e9641)
		ret =  XDP_DROP;
	else if(src_ip == 0x573f0bcb)
		ret =  XDP_DROP;
	else if(src_ip == 0x159a81f3)
		ret =  XDP_DROP;
	else if(src_ip == 0x34e1e6f5)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b7c5195)
		ret =  XDP_DROP;
	else if(src_ip == 0x144973e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5748ab3)
		ret =  XDP_DROP;
	else if(src_ip == 0x6322ac9f)
		ret =  XDP_DROP;
	else if(src_ip == 0x6e080f80)
		ret =  XDP_DROP;
	else if(src_ip == 0x4357182c)
		ret =  XDP_DROP;
	else if(src_ip == 0x624a53b0)
		ret =  XDP_DROP;
	else if(src_ip == 0x33cdd506)
		ret =  XDP_DROP;
	else if(src_ip == 0x32302808)
		ret =  XDP_DROP;
	else if(src_ip == 0x16ed7c94)
		ret =  XDP_DROP;
	else if(src_ip == 0x6dc658ab)
		ret =  XDP_DROP;
	else if(src_ip == 0xd418ee1)
		ret =  XDP_DROP;
	else if(src_ip == 0x108ac56b)
		ret =  XDP_DROP;
	else if(src_ip == 0x366dc5b7)
		ret =  XDP_DROP;
	else if(src_ip == 0x56fe1b5e)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ab5bbb7)
		ret =  XDP_DROP;
	else if(src_ip == 0x602fa021)
		ret =  XDP_DROP;
	else if(src_ip == 0x7861233b)
		ret =  XDP_DROP;
	else if(src_ip == 0x35540b0)
		ret =  XDP_DROP;
	else if(src_ip == 0x52b37ba0)
		ret =  XDP_DROP;
	else if(src_ip == 0x23408cb4)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e461191)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c944b74)
		ret =  XDP_DROP;
	else if(src_ip == 0x2053051e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5048dd15)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c3c30bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x65221e50)
		ret =  XDP_DROP;
	else if(src_ip == 0x17977356)
		ret =  XDP_DROP;
	else if(src_ip == 0x337b3c87)
		ret =  XDP_DROP;
	else if(src_ip == 0x7abca043)
		ret =  XDP_DROP;
	else if(src_ip == 0x4c795a4b)
		ret =  XDP_DROP;
	else if(src_ip == 0x1ef78e1c)
		ret =  XDP_DROP;
	else if(src_ip == 0x7c013781)
		ret =  XDP_DROP;
	else if(src_ip == 0x51ede4fe)
		ret =  XDP_DROP;
	else if(src_ip == 0x21a3abc)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a094702)
		ret =  XDP_DROP;
	else if(src_ip == 0x1544fd2b)
		ret =  XDP_DROP;
	else if(src_ip == 0x64648e6c)
		ret =  XDP_DROP;
	else if(src_ip == 0x1dd71c08)
		ret =  XDP_DROP;
	else if(src_ip == 0x47752533)
		ret =  XDP_DROP;
	else if(src_ip == 0x7b520b00)
		ret =  XDP_DROP;
	else if(src_ip == 0xb9d74b4)
		ret =  XDP_DROP;
	else if(src_ip == 0x54b6b414)
		ret =  XDP_DROP;
	else if(src_ip == 0xbdcd06b)
		ret =  XDP_DROP;
	else if(src_ip == 0x420b3a6b)
		ret =  XDP_DROP;
	else if(src_ip == 0x2bb4cf73)
		ret =  XDP_DROP;
	else if(src_ip == 0x46928c22)
		ret =  XDP_DROP;
	else if(src_ip == 0x223ada8c)
		ret =  XDP_DROP;
	else if(src_ip == 0x2415f2ae)
		ret =  XDP_DROP;
	else if(src_ip == 0x49e7ccd2)
		ret =  XDP_DROP;
	else if(src_ip == 0x74ee562c)
		ret =  XDP_DROP;
	else if(src_ip == 0x47567f62)
		ret =  XDP_DROP;
	else if(src_ip == 0x82dde63)
		ret =  XDP_DROP;
	else if(src_ip == 0x5182a1a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x67a98480)
		ret =  XDP_DROP;
	else if(src_ip == 0x5876bb78)
		ret =  XDP_DROP;
	else if(src_ip == 0x2dbed25d)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ccba2d0)
		ret =  XDP_DROP;
	else if(src_ip == 0x700e2ece)
		ret =  XDP_DROP;
	else if(src_ip == 0x613a0ee4)
		ret =  XDP_DROP;
	else if(src_ip == 0x47884314)
		ret =  XDP_DROP;
	else if(src_ip == 0x3c87891a)
		ret =  XDP_DROP;
	else if(src_ip == 0x319d01)
		ret =  XDP_DROP;
	else if(src_ip == 0x43897a95)
		ret =  XDP_DROP;
	else if(src_ip == 0xe756e18)
		ret =  XDP_DROP;
	else if(src_ip == 0x24bd7bd)
		ret =  XDP_DROP;
	else if(src_ip == 0x2d92c197)
		ret =  XDP_DROP;
	else if(src_ip == 0x23ba6b43)
		ret =  XDP_DROP;
	else if(src_ip == 0x66b06629)
		ret =  XDP_DROP;
	else if(src_ip == 0x4b69dda0)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b2f9077)
		ret =  XDP_DROP;
	else if(src_ip == 0x62027129)
		ret =  XDP_DROP;
	else if(src_ip == 0x57075254)
		ret =  XDP_DROP;
	else if(src_ip == 0x3fe6448b)
		ret =  XDP_DROP;
	else if(src_ip == 0x6ddf4194)
		ret =  XDP_DROP;
	else if(src_ip == 0x19128cbf)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b9b13fe)
		ret =  XDP_DROP;
	else if(src_ip == 0x3471cdb7)
		ret =  XDP_DROP;
	else if(src_ip == 0x3b4d674b)
		ret =  XDP_DROP;
	else if(src_ip == 0xfb106ac)
		ret =  XDP_DROP;
	else if(src_ip == 0x7e599a89)
		ret =  XDP_DROP;
	else if(src_ip == 0x303bbd78)
		ret =  XDP_DROP;
	else if(src_ip == 0x5707860e)
		ret =  XDP_DROP;
	else if(src_ip == 0x68778ed)
		ret =  XDP_DROP;
	else if(src_ip == 0x1be5f18)
		ret =  XDP_DROP;
	else if(src_ip == 0x3eb10a8e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5efe3465)
		ret =  XDP_DROP;
	else if(src_ip == 0x2f7d3175)
		ret =  XDP_DROP;
	else if(src_ip == 0xb7cad5f)
		ret =  XDP_DROP;
	else if(src_ip == 0x4f0c6334)
		ret =  XDP_DROP;
	else if(src_ip == 0x10b7405a)
		ret =  XDP_DROP;
	else if(src_ip == 0x5304f073)
		ret =  XDP_DROP;
	else if(src_ip == 0xb93ec4e)
		ret =  XDP_DROP;
	else if(src_ip == 0x10e8dd5b)
		ret =  XDP_DROP;
	else if(src_ip == 0x168e6b08)
		ret =  XDP_DROP;
	else if(src_ip == 0x1a095a66)
		ret =  XDP_DROP;
	else if(src_ip == 0x1334b518)
		ret =  XDP_DROP;
	else if(src_ip == 0x44212ca0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3dc3c5aa)
		ret =  XDP_DROP;
	else if(src_ip == 0x79e51b41)
		ret =  XDP_DROP;
	else if(src_ip == 0xf8b0a40)
		ret =  XDP_DROP;
	else if(src_ip == 0x28f35621)
		ret =  XDP_DROP;
	else if(src_ip == 0x5be78c6a)
		ret =  XDP_DROP;
	else if(src_ip == 0x66925c94)
		ret =  XDP_DROP;
	else if(src_ip == 0x68d99aac)
		ret =  XDP_DROP;
	else if(src_ip == 0x49c6cdfe)
		ret =  XDP_DROP;
	else if(src_ip == 0x7fa4e953)
		ret =  XDP_DROP;
	else if(src_ip == 0x5474aeab)
		ret =  XDP_DROP;
	else if(src_ip == 0x7e389bb5)
		ret =  XDP_DROP;
	else if(src_ip == 0x3af2509e)
		ret =  XDP_DROP;
	else if(src_ip == 0x6425b557)
		ret =  XDP_DROP;
	else if(src_ip == 0x7c92363f)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b2e0e16)
		ret =  XDP_DROP;
	else if(src_ip == 0x3b2d3b66)
		ret =  XDP_DROP;
	else if(src_ip == 0x319af2c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6cec6d2f)
		ret =  XDP_DROP;
	else if(src_ip == 0x79de45f4)
		ret =  XDP_DROP;
	else if(src_ip == 0x6217e391)
		ret =  XDP_DROP;
	else if(src_ip == 0x1c699ea4)
		ret =  XDP_DROP;
	else if(src_ip == 0x55af353)
		ret =  XDP_DROP;
	else if(src_ip == 0x312446c5)
		ret =  XDP_DROP;
	else if(src_ip == 0x2d20defe)
		ret =  XDP_DROP;
	else if(src_ip == 0x585fe3c6)
		ret =  XDP_DROP;
	else if(src_ip == 0x3cb83313)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e09bc59)
		ret =  XDP_DROP;
	else if(src_ip == 0x6eee4ecf)
		ret =  XDP_DROP;
	else if(src_ip == 0x56c18d7a)
		ret =  XDP_DROP;
	else if(src_ip == 0x513e7171)
		ret =  XDP_DROP;
	else if(src_ip == 0x330f7b6f)
		ret =  XDP_DROP;
	else if(src_ip == 0x14855324)
		ret =  XDP_DROP;
	else if(src_ip == 0x4b238cb2)
		ret =  XDP_DROP;
	else if(src_ip == 0x429a85af)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d78a945)
		ret =  XDP_DROP;
	else if(src_ip == 0x270b191c)
		ret =  XDP_DROP;
	else if(src_ip == 0x292ce243)
		ret =  XDP_DROP;
	else if(src_ip == 0x265243f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x70d1e71b)
		ret =  XDP_DROP;
	else if(src_ip == 0x28d1cb96)
		ret =  XDP_DROP;
	else if(src_ip == 0x7ac6f29c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f0a82d0)
		ret =  XDP_DROP;
	else if(src_ip == 0x63c41c34)
		ret =  XDP_DROP;
	else if(src_ip == 0x5eeca7f4)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b9cb90f)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ef22a4b)
		ret =  XDP_DROP;
	else if(src_ip == 0x1a19e35a)
		ret =  XDP_DROP;
	else if(src_ip == 0x6eb6683b)
		ret =  XDP_DROP;
	else if(src_ip == 0x3bde977a)
		ret =  XDP_DROP;
	else if(src_ip == 0x13f8294e)
		ret =  XDP_DROP;
	else if(src_ip == 0x50ce4bcd)
		ret =  XDP_DROP;
	else if(src_ip == 0x5848361e)
		ret =  XDP_DROP;
	else if(src_ip == 0x19531ca2)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f29292)
		ret =  XDP_DROP;
	else if(src_ip == 0x569151d)
		ret =  XDP_DROP;
	else if(src_ip == 0x71b30068)
		ret =  XDP_DROP;
	else if(src_ip == 0x3eaac5a6)
		ret =  XDP_DROP;
	else if(src_ip == 0x4372d176)
		ret =  XDP_DROP;
	else if(src_ip == 0x60a14f37)
		ret =  XDP_DROP;
	else if(src_ip == 0x156c5320)
		ret =  XDP_DROP;
	else if(src_ip == 0x14b142e8)
		ret =  XDP_DROP;
	else if(src_ip == 0x13b0caa6)
		ret =  XDP_DROP;
	else if(src_ip == 0x29f1a644)
		ret =  XDP_DROP;
	else if(src_ip == 0x5fd4cf9a)
		ret =  XDP_DROP;
	else if(src_ip == 0x564b5055)
		ret =  XDP_DROP;
	else if(src_ip == 0x676a4f89)
		ret =  XDP_DROP;
	else if(src_ip == 0x6dfe8b7)
		ret =  XDP_DROP;
	else if(src_ip == 0x7f783298)
		ret =  XDP_DROP;
	else if(src_ip == 0xdbc937a)
		ret =  XDP_DROP;
	else if(src_ip == 0x77b1cfd2)
		ret =  XDP_DROP;
	else if(src_ip == 0x2849fe2e)
		ret =  XDP_DROP;
	else if(src_ip == 0x8838617)
		ret =  XDP_DROP;
	else if(src_ip == 0x66bc52a2)
		ret =  XDP_DROP;
	else if(src_ip == 0xc0e1a63)
		ret =  XDP_DROP;
	else if(src_ip == 0x67702e0b)
		ret =  XDP_DROP;
	else if(src_ip == 0x52590bb2)
		ret =  XDP_DROP;
	else if(src_ip == 0x5b0044ae)
		ret =  XDP_DROP;
	else if(src_ip == 0x18a1165)
		ret =  XDP_DROP;
	else if(src_ip == 0x410f73ed)
		ret =  XDP_DROP;
	else if(src_ip == 0x16dedc28)
		ret =  XDP_DROP;
	else if(src_ip == 0x15823ab3)
		ret =  XDP_DROP;
	else if(src_ip == 0x11ddbfba)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f271246)
		ret =  XDP_DROP;
	else if(src_ip == 0x2ed55755)
		ret =  XDP_DROP;
	else if(src_ip == 0x13d0524d)
		ret =  XDP_DROP;
	else if(src_ip == 0x74902763)
		ret =  XDP_DROP;
	else if(src_ip == 0x208857be)
		ret =  XDP_DROP;
	else if(src_ip == 0x527b17f3)
		ret =  XDP_DROP;
	else if(src_ip == 0x3802f8da)
		ret =  XDP_DROP;
	else if(src_ip == 0x129a6f5)
		ret =  XDP_DROP;
	else if(src_ip == 0x67e76b13)
		ret =  XDP_DROP;
	else if(src_ip == 0x4cb43bc2)
		ret =  XDP_DROP;
	else if(src_ip == 0x14da719c)
		ret =  XDP_DROP;
	else if(src_ip == 0x11d91157)
		ret =  XDP_DROP;
	else if(src_ip == 0x2c890b5c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b25c1f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x794360e0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3368f413)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a9df48a)
		ret =  XDP_DROP;
	else if(src_ip == 0x6fff45a)
		ret =  XDP_DROP;
	else if(src_ip == 0x2b1ac3e5)
		ret =  XDP_DROP;
	else if(src_ip == 0x12e7f2b8)
		ret =  XDP_DROP;
	else if(src_ip == 0xf837a71)
		ret =  XDP_DROP;
	else if(src_ip == 0x11d71688)
		ret =  XDP_DROP;
	else if(src_ip == 0x1ef60d1b)
		ret =  XDP_DROP;
	else if(src_ip == 0x76f3a87c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6430223a)
		ret =  XDP_DROP;
	else if(src_ip == 0x79f651c9)
		ret =  XDP_DROP;
	else if(src_ip == 0x787db9e1)
		ret =  XDP_DROP;
	else if(src_ip == 0x253f9627)
		ret =  XDP_DROP;
	else if(src_ip == 0x10d52df1)
		ret =  XDP_DROP;
	else if(src_ip == 0xdfff495)
		ret =  XDP_DROP;
	else if(src_ip == 0x371d55e2)
		ret =  XDP_DROP;
	else if(src_ip == 0x7ffc4038)
		ret =  XDP_DROP;
	else if(src_ip == 0x3cd54bea)
		ret =  XDP_DROP;
	else if(src_ip == 0x4aeda82f)
		ret =  XDP_DROP;
	else if(src_ip == 0x748c679b)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d5da3a8)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d68c022)
		ret =  XDP_DROP;
	else if(src_ip == 0x2c8f6075)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e874a9e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5502b35)
		ret =  XDP_DROP;
	else if(src_ip == 0x79439c37)
		ret =  XDP_DROP;
	else if(src_ip == 0x7361bc3a)
		ret =  XDP_DROP;
	else if(src_ip == 0x17293c8c)
		ret =  XDP_DROP;
	else if(src_ip == 0x25cca794)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e877e2b)
		ret =  XDP_DROP;
	else if(src_ip == 0x106c9d6c)
		ret =  XDP_DROP;
	else if(src_ip == 0x59359ba7)
		ret =  XDP_DROP;
	else if(src_ip == 0x492572b5)
		ret =  XDP_DROP;
	else if(src_ip == 0x176c91c6)
		ret =  XDP_DROP;
	else if(src_ip == 0x4505f8d)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c0d656e)
		ret =  XDP_DROP;
	else if(src_ip == 0x26f00c38)
		ret =  XDP_DROP;
	else if(src_ip == 0x16277615)
		ret =  XDP_DROP;
	else if(src_ip == 0x7b037289)
		ret =  XDP_DROP;
	else if(src_ip == 0x1de3b4b4)
		ret =  XDP_DROP;
	else if(src_ip == 0x7a57984f)
		ret =  XDP_DROP;
	else if(src_ip == 0x74f9c453)
		ret =  XDP_DROP;
	else if(src_ip == 0x16616e96)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f972e76)
		ret =  XDP_DROP;
	else if(src_ip == 0x5cef244)
		ret =  XDP_DROP;
	else if(src_ip == 0x2461632b)
		ret =  XDP_DROP;
	else if(src_ip == 0x56b48458)
		ret =  XDP_DROP;
	else if(src_ip == 0x5cb327c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6136af15)
		ret =  XDP_DROP;
	else if(src_ip == 0x21a22c87)
		ret =  XDP_DROP;
	else if(src_ip == 0x7a579a18)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e9452be)
		ret =  XDP_DROP;
	else if(src_ip == 0x3f0aeca9)
		ret =  XDP_DROP;
	else if(src_ip == 0x26e6fa8d)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d1b9d5c)
		ret =  XDP_DROP;
	else if(src_ip == 0x445b17de)
		ret =  XDP_DROP;
	else if(src_ip == 0x202a96c5)
		ret =  XDP_DROP;
	else if(src_ip == 0x107d5996)
		ret =  XDP_DROP;
	else if(src_ip == 0x5b84546a)
		ret =  XDP_DROP;
	else if(src_ip == 0x45f73e59)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f04d7c1)
		ret =  XDP_DROP;
	else if(src_ip == 0x6bf0f1d6)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f2cda00)
		ret =  XDP_DROP;
	else if(src_ip == 0x382a4a77)
		ret =  XDP_DROP;
	else if(src_ip == 0x35d839d)
		ret =  XDP_DROP;
	else if(src_ip == 0x237d398d)
		ret =  XDP_DROP;
	else if(src_ip == 0x1437afe5)
		ret =  XDP_DROP;
	else if(src_ip == 0x2a4d8fd5)
		ret =  XDP_DROP;
	else if(src_ip == 0x39a4afa2)
		ret =  XDP_DROP;
	else if(src_ip == 0xf3b226e)
		ret =  XDP_DROP;
	else if(src_ip == 0x48314489)
		ret =  XDP_DROP;
	else if(src_ip == 0x33fc47f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x434e6c1)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e92b31f)
		ret =  XDP_DROP;
	else if(src_ip == 0x53937668)
		ret =  XDP_DROP;
	else if(src_ip == 0xa03d906)
		ret =  XDP_DROP;
	else if(src_ip == 0x2f4164a)
		ret =  XDP_DROP;
	else if(src_ip == 0x2a47fac0)
		ret =  XDP_DROP;
	else if(src_ip == 0xfcf0b82)
		ret =  XDP_DROP;
	else if(src_ip == 0x642ac560)
		ret =  XDP_DROP;
	else if(src_ip == 0x4bea2748)
		ret =  XDP_DROP;
	else if(src_ip == 0xa26a59a)
		ret =  XDP_DROP;
	else if(src_ip == 0x22bf181e)
		ret =  XDP_DROP;
	else if(src_ip == 0xaf513f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x310da028)
		ret =  XDP_DROP;
	else if(src_ip == 0x3fdab57a)
		ret =  XDP_DROP;
	else if(src_ip == 0x4f502bd0)
		ret =  XDP_DROP;
	else if(src_ip == 0x513836ed)
		ret =  XDP_DROP;
	else if(src_ip == 0x50580f10)
		ret =  XDP_DROP;
	else if(src_ip == 0x2ad4803a)
		ret =  XDP_DROP;
	else if(src_ip == 0x172f7546)
		ret =  XDP_DROP;
	else if(src_ip == 0x3f5ce6d1)
		ret =  XDP_DROP;
	else if(src_ip == 0x16c57211)
		ret =  XDP_DROP;
	else if(src_ip == 0x365c4f46)
		ret =  XDP_DROP;
	else if(src_ip == 0x77873148)
		ret =  XDP_DROP;
	else if(src_ip == 0x1a22f5ae)
		ret =  XDP_DROP;
	else if(src_ip == 0x59d988d4)
		ret =  XDP_DROP;
	else if(src_ip == 0xbbee12d)
		ret =  XDP_DROP;
	else if(src_ip == 0x44708583)
		ret =  XDP_DROP;
	else if(src_ip == 0x137e3876)
		ret =  XDP_DROP;
	else if(src_ip == 0x1afa039c)
		ret =  XDP_DROP;
	else if(src_ip == 0xca1ca0c)
		ret =  XDP_DROP;
	else if(src_ip == 0x477a8068)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f2eea5d)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b347d2c)
		ret =  XDP_DROP;
	else if(src_ip == 0x1b0df6d0)
		ret =  XDP_DROP;
	else if(src_ip == 0x2932c363)
		ret =  XDP_DROP;
	else if(src_ip == 0x6e289376)
		ret =  XDP_DROP;
	else if(src_ip == 0x4555f190)
		ret =  XDP_DROP;
	else if(src_ip == 0x3901cee6)
		ret =  XDP_DROP;
	else if(src_ip == 0x525358d6)
		ret =  XDP_DROP;
	else if(src_ip == 0x114018d8)
		ret =  XDP_DROP;
	else if(src_ip == 0x43287480)
		ret =  XDP_DROP;
	else if(src_ip == 0x751270f4)
		ret =  XDP_DROP;
	else if(src_ip == 0x1c352cca)
		ret =  XDP_DROP;
	else if(src_ip == 0x743614a8)
		ret =  XDP_DROP;
	else if(src_ip == 0x34ed266e)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b85589a)
		ret =  XDP_DROP;
	else if(src_ip == 0x456e4b95)
		ret =  XDP_DROP;
	else if(src_ip == 0x545357e)
		ret =  XDP_DROP;
	else if(src_ip == 0x1659d8d4)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c9dc0db)
		ret =  XDP_DROP;
	else if(src_ip == 0x44a21c50)
		ret =  XDP_DROP;
	else if(src_ip == 0x2d1f4ae5)
		ret =  XDP_DROP;
	else if(src_ip == 0x12fa1022)
		ret =  XDP_DROP;
	else if(src_ip == 0x3c294d98)
		ret =  XDP_DROP;
	else if(src_ip == 0x47424093)
		ret =  XDP_DROP;
	else if(src_ip == 0x6cd398f6)
		ret =  XDP_DROP;
	else if(src_ip == 0x47e82ec6)
		ret =  XDP_DROP;
	else if(src_ip == 0xbb2c616)
		ret =  XDP_DROP;
	else if(src_ip == 0x51d16c)
		ret =  XDP_DROP;
	else if(src_ip == 0x62e23262)
		ret =  XDP_DROP;
	else if(src_ip == 0x18549023)
		ret =  XDP_DROP;
	else if(src_ip == 0x47cc51d4)
		ret =  XDP_DROP;
	else if(src_ip == 0x2111cbf)
		ret =  XDP_DROP;
	else if(src_ip == 0x3890d4f)
		ret =  XDP_DROP;
	else if(src_ip == 0x62da48a4)
		ret =  XDP_DROP;
	else if(src_ip == 0x2b43e023)
		ret =  XDP_DROP;
	else if(src_ip == 0x71b1a0c5)
		ret =  XDP_DROP;
	else if(src_ip == 0x28303a35)
		ret =  XDP_DROP;
	else if(src_ip == 0x6445af09)
		ret =  XDP_DROP;
	else if(src_ip == 0x4404f99c)
		ret =  XDP_DROP;
	else if(src_ip == 0x3970530d)
		ret =  XDP_DROP;
	else if(src_ip == 0x276e2389)
		ret =  XDP_DROP;
	else if(src_ip == 0x39176a90)
		ret =  XDP_DROP;
	else if(src_ip == 0x55a57fd7)
		ret =  XDP_DROP;
	else if(src_ip == 0x1ba43832)
		ret =  XDP_DROP;
	else if(src_ip == 0x6e0490ff)
		ret =  XDP_DROP;
	else if(src_ip == 0x412ad871)
		ret =  XDP_DROP;
	else if(src_ip == 0x611283c7)
		ret =  XDP_DROP;
	else if(src_ip == 0x7349c67d)
		ret =  XDP_DROP;
	else if(src_ip == 0x5784b146)
		ret =  XDP_DROP;
	else if(src_ip == 0x3db044a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x37ebe2cd)
		ret =  XDP_DROP;
	else if(src_ip == 0x4a3fc2b)
		ret =  XDP_DROP;
	else if(src_ip == 0x50aa54c5)
		ret =  XDP_DROP;
	else if(src_ip == 0x74153066)
		ret =  XDP_DROP;
	else if(src_ip == 0x4be63cbf)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d7dedbb)
		ret =  XDP_DROP;
	else if(src_ip == 0x3bfd5f2c)
		ret =  XDP_DROP;
	else if(src_ip == 0x579902d5)
		ret =  XDP_DROP;
	else if(src_ip == 0x3dcfbf27)
		ret =  XDP_DROP;
	else if(src_ip == 0x1edf918e)
		ret =  XDP_DROP;
	else if(src_ip == 0x6fed92f8)
		ret =  XDP_DROP;
	else if(src_ip == 0x59c10fc)
		ret =  XDP_DROP;
	else if(src_ip == 0x20f0ae4d)
		ret =  XDP_DROP;
	else if(src_ip == 0x7376a047)
		ret =  XDP_DROP;
	else if(src_ip == 0x687659a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x4c348e70)
		ret =  XDP_DROP;
	else if(src_ip == 0x6528410d)
		ret =  XDP_DROP;
	else if(src_ip == 0x10a693d5)
		ret =  XDP_DROP;
	else if(src_ip == 0x307a3d79)
		ret =  XDP_DROP;
	else if(src_ip == 0x292d3aa9)
		ret =  XDP_DROP;
	else if(src_ip == 0x4a16e6e3)
		ret =  XDP_DROP;
	else if(src_ip == 0x57e86103)
		ret =  XDP_DROP;
	else if(src_ip == 0x6244a539)
		ret =  XDP_DROP;
	else if(src_ip == 0x1fbc66ba)
		ret =  XDP_DROP;
	else if(src_ip == 0x738c9935)
		ret =  XDP_DROP;
	else if(src_ip == 0x50493638)
		ret =  XDP_DROP;
	else if(src_ip == 0x60e73f2c)
		ret =  XDP_DROP;
	else if(src_ip == 0x549f1cfc)
		ret =  XDP_DROP;
	else if(src_ip == 0x4392fcb6)
		ret =  XDP_DROP;
	else if(src_ip == 0x386bf072)
		ret =  XDP_DROP;
	else if(src_ip == 0x124f619f)
		ret =  XDP_DROP;
	else if(src_ip == 0x7b7edf83)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d0fec9d)
		ret =  XDP_DROP;
	else if(src_ip == 0x62f9b664)
		ret =  XDP_DROP;
	else if(src_ip == 0x6f940fe9)
		ret =  XDP_DROP;
	else if(src_ip == 0x8f6295c)
		ret =  XDP_DROP;
	else if(src_ip == 0x2077a41f)
		ret =  XDP_DROP;
	else if(src_ip == 0x2b916f15)
		ret =  XDP_DROP;
	else if(src_ip == 0x608f2c32)
		ret =  XDP_DROP;
	else if(src_ip == 0x5e476347)
		ret =  XDP_DROP;
	else if(src_ip == 0x4a7100a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x507cbf2a)
		ret =  XDP_DROP;
	else if(src_ip == 0x63e37443)
		ret =  XDP_DROP;
	else if(src_ip == 0x6b61aef1)
		ret =  XDP_DROP;
	else if(src_ip == 0x43f35f72)
		ret =  XDP_DROP;
	else if(src_ip == 0x4c59cde3)
		ret =  XDP_DROP;
	else if(src_ip == 0x37963d61)
		ret =  XDP_DROP;
	else if(src_ip == 0x291ba07f)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d0061b9)
		ret =  XDP_DROP;
	else if(src_ip == 0x68107adb)
		ret =  XDP_DROP;
	else if(src_ip == 0x5248db28)
		ret =  XDP_DROP;
	else if(src_ip == 0x2717489c)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ff8dbde)
		ret =  XDP_DROP;
	else if(src_ip == 0x348d8061)
		ret =  XDP_DROP;
	else if(src_ip == 0x46d3af56)
		ret =  XDP_DROP;
	else if(src_ip == 0x33857513)
		ret =  XDP_DROP;
	else if(src_ip == 0x4d6b69a)
		ret =  XDP_DROP;
	else if(src_ip == 0x27baee82)
		ret =  XDP_DROP;
	else if(src_ip == 0x824920f)
		ret =  XDP_DROP;
	else if(src_ip == 0x4869b350)
		ret =  XDP_DROP;
	else if(src_ip == 0x6026def4)
		ret =  XDP_DROP;
	else if(src_ip == 0x1a73f3af)
		ret =  XDP_DROP;
	else if(src_ip == 0x43e892d3)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d36cb92)
		ret =  XDP_DROP;
	else if(src_ip == 0x7d6daa13)
		ret =  XDP_DROP;
	else if(src_ip == 0x337ca2bd)
		ret =  XDP_DROP;
	else if(src_ip == 0x262cf4ee)
		ret =  XDP_DROP;
	else if(src_ip == 0x1de54e33)
		ret =  XDP_DROP;
	else if(src_ip == 0x5f0e11d2)
		ret =  XDP_DROP;
	else if(src_ip == 0x6bc2120)
		ret =  XDP_DROP;
	else if(src_ip == 0x7c2cb17a)
		ret =  XDP_DROP;
	else if(src_ip == 0x297f1276)
		ret =  XDP_DROP;
	else if(src_ip == 0x5738e04b)
		ret =  XDP_DROP;
	else if(src_ip == 0x601025bd)
		ret =  XDP_DROP;
	else if(src_ip == 0x14e0c167)
		ret =  XDP_DROP;
	else if(src_ip == 0x1b2c3fbd)
		ret =  XDP_DROP;
	else if(src_ip == 0x2c69f3a0)
		ret =  XDP_DROP;
	else if(src_ip == 0x4c76fec8)
		ret =  XDP_DROP;
	else if(src_ip == 0x4447e03c)
		ret =  XDP_DROP;
	else if(src_ip == 0x96a5559)
		ret =  XDP_DROP;
	else if(src_ip == 0x348779a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x1690bb64)
		ret =  XDP_DROP;
	else if(src_ip == 0x30819df5)
		ret =  XDP_DROP;
	else if(src_ip == 0x74805581)
		ret =  XDP_DROP;
	else if(src_ip == 0x4b1e3bc5)
		ret =  XDP_DROP;
	else if(src_ip == 0x77554d4c)
		ret =  XDP_DROP;
	else if(src_ip == 0x2805ca94)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ff4f25f)
		ret =  XDP_DROP;
	else if(src_ip == 0x1f103bce)
		ret =  XDP_DROP;
	else if(src_ip == 0x302a5ca4)
		ret =  XDP_DROP;
	else if(src_ip == 0x185ea5af)
		ret =  XDP_DROP;
	else if(src_ip == 0x7f371ac3)
		ret =  XDP_DROP;
	else if(src_ip == 0x4a9e5053)
		ret =  XDP_DROP;
	else if(src_ip == 0x5c473883)
		ret =  XDP_DROP;
	else if(src_ip == 0x1c6de655)
		ret =  XDP_DROP;
	else if(src_ip == 0x480bfa66)
		ret =  XDP_DROP;
	else if(src_ip == 0xfc3db40)
		ret =  XDP_DROP;
	else if(src_ip == 0x429adb43)
		ret =  XDP_DROP;
	else if(src_ip == 0x65f14899)
		ret =  XDP_DROP;
	else if(src_ip == 0x6ed1ed12)
		ret =  XDP_DROP;
	else if(src_ip == 0x4956fc64)
		ret =  XDP_DROP;
	else if(src_ip == 0x621dfa13)
		ret =  XDP_DROP;
	else if(src_ip == 0x1850ff88)
		ret =  XDP_DROP;
	else if(src_ip == 0x208fdcaf)
		ret =  XDP_DROP;
	else if(src_ip == 0x422e1fd0)
		ret =  XDP_DROP;
	else if(src_ip == 0x2d31c0ef)
		ret =  XDP_DROP;
	else if(src_ip == 0x3bbc1c6c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6e981371)
		ret =  XDP_DROP;
	else if(src_ip == 0x79a8bfb8)
		ret =  XDP_DROP;
	else if(src_ip == 0x3fca8)
		ret =  XDP_DROP;
	else if(src_ip == 0x780268ca)
		ret =  XDP_DROP;
	else if(src_ip == 0x2e30395b)
		ret =  XDP_DROP;
	else if(src_ip == 0x1694b80c)
		ret =  XDP_DROP;
	else if(src_ip == 0x288406c0)
		ret =  XDP_DROP;
	else if(src_ip == 0x22b08edd)
		ret =  XDP_DROP;
	else if(src_ip == 0x61b2f3d1)
		ret =  XDP_DROP;
	else if(src_ip == 0x1fd9540c)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ab65971)
		ret =  XDP_DROP;
	else if(src_ip == 0x31a7e631)
		ret =  XDP_DROP;
	else if(src_ip == 0x3ee98fda)
		ret =  XDP_DROP;
	else if(src_ip == 0x7ae0b615)
		ret =  XDP_DROP;
	else if(src_ip == 0x4a068be0)
		ret =  XDP_DROP;
	else if(src_ip == 0x3e20aa9d)
		ret =  XDP_DROP;
	else if(src_ip == 0x457f0668)
		ret =  XDP_DROP;
	else if(src_ip == 0x264dc463)
		ret =  XDP_DROP;
	else if(src_ip == 0x5a8e90f2)
		ret =  XDP_DROP;
	else if(src_ip == 0xd8b00cf)
		ret =  XDP_DROP;
	else if(src_ip == 0x36119fa3)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d296c36)
		ret =  XDP_DROP;
	else if(src_ip == 0x737c4968)
		ret =  XDP_DROP;
	else if(src_ip == 0x24e38cb6)
		ret =  XDP_DROP;
	else if(src_ip == 0x6680689a)
		ret =  XDP_DROP;
	else if(src_ip == 0x559a437c)
		ret =  XDP_DROP;
	else if(src_ip == 0x3d348c3e)
		ret =  XDP_DROP;
	else if(src_ip == 0x7104549)
		ret =  XDP_DROP;
	else if(src_ip == 0x17c8634c)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a664d2e)
		ret =  XDP_DROP;
	else if(src_ip == 0x42cc61b5)
		ret =  XDP_DROP;
	else if(src_ip == 0x66076bd)
		ret =  XDP_DROP;
	else if(src_ip == 0x640f0ce6)
		ret =  XDP_DROP;
	else if(src_ip == 0x42d05e5d)
		ret =  XDP_DROP;
	else if(src_ip == 0x7e62df88)
		ret =  XDP_DROP;
	else if(src_ip == 0x123f4641)
		ret =  XDP_DROP;
	else if(src_ip == 0x59651669)
		ret =  XDP_DROP;
	else if(src_ip == 0x26e6e648)
		ret =  XDP_DROP;
	else if(src_ip == 0x34efd51e)
		ret =  XDP_DROP;
	else if(src_ip == 0x3b180a3a)
		ret =  XDP_DROP;
	else if(src_ip == 0x46c03a54)
		ret =  XDP_DROP;
	else if(src_ip == 0x7fa62e90)
		ret =  XDP_DROP;
	else if(src_ip == 0x6cbff06b)
		ret =  XDP_DROP;
	else if(src_ip == 0x5a9ca2e)
		ret =  XDP_DROP;
	else if(src_ip == 0x7a86e4a5)
		ret =  XDP_DROP;
	else if(src_ip == 0x36c67c4c)
		ret =  XDP_DROP;
	else if(src_ip == 0x43ca74cc)
		ret =  XDP_DROP;
	else if(src_ip == 0x4005eb0e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d1440af)
		ret =  XDP_DROP;
	else if(src_ip == 0x1e5905be)
		ret =  XDP_DROP;
	else if(src_ip == 0x4d90ebdd)
		ret =  XDP_DROP;
	else if(src_ip == 0x1325e053)
		ret =  XDP_DROP;
	else if(src_ip == 0x3b8271f4)
		ret =  XDP_DROP;
	else if(src_ip == 0x410d3545)
		ret =  XDP_DROP;
	else if(src_ip == 0x38096d09)
		ret =  XDP_DROP;
	else if(src_ip == 0x2202da8e)
		ret =  XDP_DROP;
	else if(src_ip == 0x16a778c1)
		ret =  XDP_DROP;
	else if(src_ip == 0x753df947)
		ret =  XDP_DROP;
	else if(src_ip == 0x29131fd7)
		ret =  XDP_DROP;
	else if(src_ip == 0x2e6fdc0e)
		ret =  XDP_DROP;
	else if(src_ip == 0x5fa44675)
		ret =  XDP_DROP;
	else if(src_ip == 0x6bdf818c)
		ret =  XDP_DROP;
	else if(src_ip == 0x34d052cb)
		ret =  XDP_DROP;
	else if(src_ip == 0x43b3535b)
		ret =  XDP_DROP;
	else if(src_ip == 0x2eafdfe9)
		ret =  XDP_DROP;
	else if(src_ip == 0x33333253)
		ret =  XDP_DROP;
	else if(src_ip == 0x55f2999d)
		ret =  XDP_DROP;
	else if(src_ip == 0x814f652)
		ret =  XDP_DROP;
	else if(src_ip == 0x5a1a189b)
		ret =  XDP_DROP;
	else if(src_ip == 0xae26ebb)
		ret =  XDP_DROP;
	else if(src_ip == 0x432d008d)
		ret =  XDP_DROP;
	else if(src_ip == 0x20da52ef)
		ret =  XDP_DROP;
	else if(src_ip == 0xa889d4b)
		ret =  XDP_DROP;
	else if(src_ip == 0x2fecf0f8)
		ret =  XDP_DROP;
	else if(src_ip == 0x26841d1e)
		ret =  XDP_DROP;
	else if(src_ip == 0x50f81f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x66b36d44)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a4e91ea)
		ret =  XDP_DROP;
	else if(src_ip == 0x45156cff)
		ret =  XDP_DROP;
	else if(src_ip == 0x43c7adf4)
		ret =  XDP_DROP;
	else if(src_ip == 0x8a797a8)
		ret =  XDP_DROP;
	else if(src_ip == 0x12a658dc)
		ret =  XDP_DROP;
	else if(src_ip == 0x56ed8e47)
		ret =  XDP_DROP;
	else if(src_ip == 0x442a099d)
		ret =  XDP_DROP;
	else if(src_ip == 0x53b38e21)
		ret =  XDP_DROP;
	else if(src_ip == 0xef6fb50)
		ret =  XDP_DROP;
	else if(src_ip == 0x662ce42b)
		ret =  XDP_DROP;
	else if(src_ip == 0x6a5b06e3)
		ret =  XDP_DROP;
	else if(src_ip == 0x434f497)
		ret =  XDP_DROP;
	else if(src_ip == 0xf400403)
		ret =  XDP_DROP;
	else if(src_ip == 0x18cae2f1)
		ret =  XDP_DROP;
	else if(src_ip == 0x63d93b0d)
		ret =  XDP_DROP;
	else if(src_ip == 0x7b1f858f)
		ret =  XDP_DROP;
	else if(src_ip == 0x4d9b35bc)
		ret =  XDP_DROP;
	else if(src_ip == 0x278c8e68)
		ret =  XDP_DROP;
	else if(src_ip == 0x29cf6579)
		ret =  XDP_DROP;
	else if(src_ip == 0xce6810)
		ret =  XDP_DROP;
	else if(src_ip == 0x7d7f2805)
		ret =  XDP_DROP;
	else if(src_ip == 0x31e45bcb)
		ret =  XDP_DROP;
	else if(src_ip == 0x5ae880ab)
		ret =  XDP_DROP;
	else if(src_ip == 0x86196c1)
		ret =  XDP_DROP;
	else if(src_ip == 0x75115c58)
		ret =  XDP_DROP;
	else if(src_ip == 0x7bc2d39b)
		ret =  XDP_DROP;
	else if(src_ip == 0x12ea340c)
		ret =  XDP_DROP;
	else if(src_ip == 0x24fe4d51)
		ret =  XDP_DROP;
	else if(src_ip == 0x2246f0b9)
		ret =  XDP_DROP;
	else if(src_ip == 0x17f9b5fd)
		ret =  XDP_DROP;
	else if(src_ip == 0xbb1ba95)
		ret =  XDP_DROP;
	else if(src_ip == 0xc9582a3)
		ret =  XDP_DROP;
	else if(src_ip == 0x5d0f22fc)
		ret =  XDP_DROP;
	else if(src_ip == 0x4f796889)
		ret =  XDP_DROP;
	else if(src_ip == 0x153d1a4b)
		ret =  XDP_DROP;
	else if(src_ip == 0x6fb57bd8)
		ret =  XDP_DROP;
	else if(src_ip == 0x2666f6d0)
		ret =  XDP_DROP;
	else if(src_ip == 0x596723e8)
		ret =  XDP_DROP;
	else if(src_ip == 0x436909fa)
		ret =  XDP_DROP;
	else if(src_ip == 0x355df220)
		ret =  XDP_DROP;
	else if(src_ip == 0x3f940814)
		ret =  XDP_DROP;
	else if(src_ip == 0x2dc410dd)
		ret =  XDP_DROP;
	else if(src_ip == 0x3992e6b8)
		ret =  XDP_DROP;
	else if(src_ip == 0x4ed40c17)
		ret =  XDP_DROP;
	else if(src_ip == 0x468ef3ce)
		ret =  XDP_DROP;
	else if(src_ip == 0x1d6c21c5)
		ret =  XDP_DROP;

	return ret;
}

char license[] SEC("license") = "GPL";

