#include "bpf_api.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

__section("bpf") int bpf_main(struct __sk_buff *skb)
{
	uint32_t src_ip;
	int nh_off = BPF_LL_OFF + ETH_HLEN;
	int ret = TC_ACT_OK;

	src_ip = load_word(skb, nh_off+offsetof(struct iphdr, saddr));
	if(src_ip == 0x6db66e3a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b210537)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x29b7daab)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x42ac1619)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xe4a10e9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x67338266)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6412f6aa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3a0614c0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc85e75f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38c4219c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x31882b48)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5002d1dc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43a3c993)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13165f07)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xbb3e17f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x132a9063)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7243420e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x70e45a3f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x54560ad0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6bb4c7ed)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3c7bb38)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x61a50b45)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6836af09)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7244db99)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4ecb3943)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2da70db)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5ca19b91)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43bad522)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5928aac1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x55b4a5d7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13e5ae53)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x46df18fb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x50d5ab0e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3d9d88fe)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x98b2f14)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5f1fbbf8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x24d10b65)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d9e25be)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1925d0b8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3156f2c4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2662475b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4aadfc00)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x159c4a1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6a0610ee)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5dc45b07)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xd0da620)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7d30a151)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x50079d15)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7df2005f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5186ac21)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3bbc6502)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1b9bb98)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x332bb767)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x23f3140c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x73fe9731)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f6f0aa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x26cd84e7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x50a032c2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x45b1c5cc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ff62fa8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2654d899)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5997741f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x46d548a3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x772a83a7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1734fd1e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x506077b8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x564a3f9f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3c060883)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3dfe9d76)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6f701058)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d5cfb47)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6460e4d1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3a1e0c58)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6eb6bfe8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4e66f5c0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x17e26760)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7bc46608)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b979711)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x67ea0475)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x79b66668)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d1e4333)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x23a66978)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b702200)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5049fa9a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x47997d84)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6f6eb931)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5240eb44)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6e67026b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x400eebf3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x17f2b111)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6e5d3214)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6663c48c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x718a2530)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35327ab7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d8e4833)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x8bf224e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x592f26f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x33d887d3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x44c52ad1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43918fe6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2348982b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x32222619)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x27f274b7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d66a483)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x20d8e601)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76596a77)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75490be3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1c9d4c0a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x41f10189)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d331059)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1653b272)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5f0f44bc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xd979d1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11c3d472)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f593f56)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4872f755)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1328da3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19a2a9a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36d9f9c0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x41417996)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x198cdbab)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25372bd4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x27a53e22)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xb1700dc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a69a68c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5338655)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13d6232a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5ffc98fb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x390c0e28)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x589b4dfc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x238e28e1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5c54a653)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xabd7415)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b809d99)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39bb4ad7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2b965a16)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x41da0810)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f0456ba)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4833a620)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3cb0999)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc376713)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e875892)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x62da4e55)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xd10e0e4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x704b2d04)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x12338dab)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5583d839)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x717dbaa7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13cdb846)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc5dd1fa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x32bf343d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2d5a93f1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3194fdce)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a64725f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x387194cd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xbfea45a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5f97f8b5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c47b7f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6bfb3d56)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x18a406dd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x24e305f4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf896637)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74f8ad31)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2fa07a09)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b0a03d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2eb3f808)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b36d41f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1ce40be1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5db84ec2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x236a7a40)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x20af157a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x69efb5d6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f1d2d2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38963d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x770096ba)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x723cffd7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x15bcf17b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c846ef4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x63baba7e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x298aa9c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x58e240ee)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1679eebc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x56e53db3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa773ebc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x70de611b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf56d280)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1675e317)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x507659d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b9e8a78)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x271206d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x691a60ae)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x81906c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11fa86a4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e130ddf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30220a75)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d048a75)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xcc705e7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xb58de95)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x9e89656)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6a7f54a9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ec358d5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2a97abd0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x546f0a7f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30b52ba7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2e210fa0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b6fa13a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x22f22b7e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43de011c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x17f4102e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6ace5fd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d68aadd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x70d6511c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d26d4b9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x444de890)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b4d8fd8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xe0535d4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x53a4bb11)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11c372ef)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e7b8fa5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f434589)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1434935c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4795f053)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2fc4d5f6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x262f1a01)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25a8fe32)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5fe6e06b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1333a476)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x32700419)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b3fbf00)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d1c3acc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1cef58c2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1a0317d5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x47b3e69c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x715e6342)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4ab8437d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75d4f63d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3cce047c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6daa6efb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39b2f759)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x54c214aa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x745754f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x271ba236)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x459865c6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x117e29b1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b698ac7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x40e5f59e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f835f86)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3f0e45d8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x52a9688e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7dfeef2b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6e518b61)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x66ddfbea)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4594df7e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1e166157)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xd0d15eb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b3dddb0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7dfd41c3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2040ba61)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1dade1c9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x693d00c3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3d5cf52d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3a9d3a8b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3401899)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x510dbca)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2bfb9dcd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4df85c16)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ae5d207)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x68c9a249)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3ba2cb11)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3498c960)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3d8bb6f3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ffa200a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5bb46b96)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3241cb9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x417849bb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x471df65d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x440a1258)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x60fba941)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x62c3c35)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x16b37ae6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5efa986c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x747dc797)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7d9176d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x248f77ea)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x129428ee)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa9e8cbc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xfcd559a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x10916ab1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2adf471d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2d7b3763)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x79ce6b75)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x683c3c4b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x681871ef)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7d0e840e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d4d1815)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x14140fbc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b06e024)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6832ea1c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7cddb206)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6a9ab35)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1ccbb37c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3a6968f9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36a3cb3f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x78801f12)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3d8d85b3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x781c14fb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3f9e1570)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x197980b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5917be3c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x45ca51a5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x184b12f1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x381256a9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3a48193c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x15dc89c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5ca1ce93)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4cdc422b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x207b167d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6c6f242e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d6dacdc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b5a5d9b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19ea5b91)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x573c1851)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x339699e6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x202cd80)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x544a9c5f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x20e3b1fb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1616dd3d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f517c83)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x9169c17)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x12f48f43)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25fb27b9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25e24f93)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4d5df83c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5c9ef2f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1e626ea5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xaeb7def)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x54bb07f3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e008415)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc8315fa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2dd2c630)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x23cad5bb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x24ce28eb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x65e51cd9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e12eef7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3aaab2ad)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4286eb6c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2aef3122)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b25c92a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ef60f9a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x85cddff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x268026c5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x48e06b2c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5f98f650)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a16c0ab)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4ae338ac)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x33e392b0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7afa72a6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x60fa15e9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x53350f33)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4110ebd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x73eea52c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x793036ec)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x29f35e50)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x414c9d69)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x55cf29e5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4855ccf6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c381b58)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2a8a31d8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2656510b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x58bb3153)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x585cf808)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4a2126c6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7d895a3e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3e4214e1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x283415be)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38340ceb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc9004e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x532346e0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1359d616)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2fbf0fe8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b8024df)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39d9fcdb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x789f7b14)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3b191b30)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13f0bd87)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4382b3c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6efcade0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xeeb302d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x247cc9aa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4231bd13)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x12fc3eeb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x186b6ed7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3b61f400)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3cef9d3b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x59b80c40)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11311de5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5456a31)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25f02798)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3bbb4fbd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2b9bbb3d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7eab58eb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x141847c6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75bce203)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7c34b32a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x525a5ca7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1df0f7c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3468c015)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x53235cf5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x71143ea2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x47c2962b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2e26cde)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c946381)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19c9307)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b81e7f2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ad7eb1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x158d508e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3f049bb3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76aa2c91)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x247880bb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6381655e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38dbe9a5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3774bfa6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7becd435)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x743ddda5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74645ce2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x55a4e075)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x56efb8a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x79a9c713)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b95080d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x412a4b47)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25458250)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7a4060f9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5542930d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1b026454)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76751423)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x279cefb5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38f35c15)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2addd438)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ac04caa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2a079ab7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x72a06a64)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7da2b988)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x769bfe39)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x743cfd6b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7924a17b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7e497cea)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x9ca4df9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38293d2e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74f3a97c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2e42ceb4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1baaa28c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2dcf9321)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x65b78e5b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x179776c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x220d70c6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a1beb3d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d3c5736)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x277c6c50)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x53c5b250)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x68d15f44)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x68a6b797)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x790b34a1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6311c03d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3de94aa5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x140d98f5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5986d460)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x65863a5a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4d00f50a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x464a898)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x60468704)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x77088fc2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x770512fc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5de9408d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6da48dfb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b421067)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x570de208)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6bee0ae5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x750c5e60)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf371f36)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x60e1b461)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x234f2d15)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ae1c1c3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xeb14782)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x906bb70)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x42793884)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30beb848)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6322a6ad)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2fb58fbb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x583b2498)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36e858fd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1886eeff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x40e1dc30)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ff38d9e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b98af3c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ecb26d5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x44012693)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x551f839c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6451612f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11021b9e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x59842c34)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4497e833)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x80aab60)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x50893f31)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x228128c0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75af395b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3bcb4f98)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x798f0ac8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x619d4440)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30d7adf9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x8c629ff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x427ef8a2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5426db0e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x33a7ebc2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x51304024)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d2d967e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76212446)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1eef86d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x40503d2b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25d6b401)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a2a1d05)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x77389628)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3e5da300)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1b0bf935)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x272c23c7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39f6523c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19d7200a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b2d4a5a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf15d5d8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7e288139)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7c2f65f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x689a020d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x42c0696d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43a1158)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3923413e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6541922d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x79e94ab3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74ee90d6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5ed09cf6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b868ef4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x25c63ecf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6796c6f5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1e058796)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x79ed19dd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1b3eb2b7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6f35c7ba)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x571ab05b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x115fd6fd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7124c027)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x176aed86)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x37368aff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b4edd2d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xea383af)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75942dff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x665ad662)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35cfa776)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f8a803c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x31f66d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x20fcf1d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3ea05614)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7e5a77a6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d2c57c9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x273a5821)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x411ae113)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x21666921)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x605d995f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x265c7341)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1b4fb3d5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x554c2a36)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x52d1037)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76d642c9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b126905)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6cc3d72c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x14dbca5f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74ff82e3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x80289e3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4119219)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c1a333e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x196260e0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75365241)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x638520c5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5098ebdf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x40852f6e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7228a474)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x462d19df)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x26e005d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x27f84bea)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75b79a1b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2711fc3d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x48f53dba)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3457f02f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x256c73e4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x66219583)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b924851)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x668754f7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x787fea5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3befe1b0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xce3c838)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x22d7b27a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x113c0be6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1210d86f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19adf543)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc4e74ec)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ed4af9b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2e89bfa2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x14df7cf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6d7397e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x329b51bb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4d682b0d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x20399a5f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x27d1a3fc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30ed4bd2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x70d2863e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6856d36a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2315f046)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36ffa01d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf36d93b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4b0e3c30)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2cb73a38)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3648d578)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x140379eb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x610f2a68)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5bb5495c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7a250f6e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3ca172b9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x423c9e54)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1ad0e13)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x78915469)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4f20668c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2484c08d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x9cd6050)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x61313efc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3e32b5d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x161bd53c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6005ee97)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6cbc7572)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1769cd0b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x66dd2816)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f57c72e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x64d1f818)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x716c275)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x47296b2a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x15bf43eb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x77e948b3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f803e95)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38d53431)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ee8e8d1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3eb717d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3e37062)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5ba02309)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x74ffed48)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x17e6ea4d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3caf4d71)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x50b536a5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x120bf9bb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7950c02a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x12f1d4f9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13b907cf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x71e21494)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x62123b85)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x383dc85c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7baf74e4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x43437a81)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76707e2d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11cb4a20)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x23496919)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x632cf39f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2935172b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa26912f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x284bacd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xe070f43)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x113d53a4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x49ae25f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x23c6532e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x9269c57)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x792e648d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5c9b8760)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x380f8528)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x37e57c5d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x607ef7c2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13afa832)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ce569a5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7865e20f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x505ef5a3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7d9aa04a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa71dbca)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x49afb5ce)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x108c7543)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1e2ae399)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3b91ca62)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x729eb0c9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5668abf6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x37413f46)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35e22b4a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4cd92a23)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x490c8966)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x592b9463)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30061dc2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7241a091)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x63522592)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x328ad890)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x48afd4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x748f7936)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7c38fe88)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x240f0303)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7db6158e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75676315)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xaa8a63)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35c59ab6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2d4cdf72)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x61298225)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x497542e8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5a324917)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x598f6434)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19d4388c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x57cce962)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x64013ffe)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6383ee5a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x68595ea5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x22c2398)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f15b8bc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5af80f6e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5894cf8e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5656f802)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x10da3ab9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x256df9b1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1f638168)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6a05cf1c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x55741773)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11a521f9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4d57f4af)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7fef003)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11edd1cd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x41e76de5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x437ee8b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35fcd4d0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3f9d8373)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x799f51a0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36a75f33)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x75631e2a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x26ec3112)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x17d0e158)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3ed86112)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11e7a2a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7160458c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x58ac999e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x58eb638c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5561858b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3c3087f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4144c231)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x578da923)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b4640b4)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1c3cd1a0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x302278b1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x319d38b6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2d170c59)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x55907262)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5100ba1e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x171cdb75)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2b0489d5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x62a5dc17)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6474d024)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x330379d9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7493ade5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x265c3e0a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x373b6864)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2a9082b5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x65f9c17d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x30daba05)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6137e1e9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5b5cdfa7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x57c6eb17)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7908c341)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1a3540ba)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x58e56541)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6a6908ce)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x72e1da58)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x31d0c8cd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3fca8e59)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f126251)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x73158aff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1758377c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa58a305)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf525c9f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x477ab02d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3bf5dbbc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3c6968f8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d0b228f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xcf695da)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5386446d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x480fac64)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6f9c71f2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x37fb1492)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b13263d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x64301fd7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5e57529c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x324e8ea2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xec0a28c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x44511419)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x632948a7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6ff88475)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1fadf3c1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3af033be)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x690147b7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39e3347b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x13d59900)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x536a5085)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2cc50ed3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x45a661cd)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1334dede)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5bd77124)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38bbeccc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2a8d165a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6630142a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x480e496b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7207c687)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2225efe6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x477b263)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xf12e916)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2f1c85c0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x57fdf6d1)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5722957a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1eb8f7b2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xff90b63)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5235bbb8)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2e91789)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6e505dff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4844a5a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x11a9ba16)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x32a17218)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x67ad9301)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1a23e8b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x524f65d9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x229dc6bf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6aa38642)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xc329a54)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x36735fbf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3e0dd6c7)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x38f7a928)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7c19c18d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5142b5a5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x14cf1a4c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x34d5ae59)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7bcfcbff)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7aff2e76)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7ce3f7c5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6dd79286)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1d251e5c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x15baa28)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7cea7b9c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4c41a41d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5959a0f9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x540d1117)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6afa9bcf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6952ac5c)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2642cccf)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6de3b359)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x57a30a5b)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x2ac71729)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7f8d6d6f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa447c74)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1274aa2a)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x12fabfa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5c93e24d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x351270e9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6bd3323d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x68c67ca2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6b85d0a9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x29e10904)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x21be25ca)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x679f9236)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x7b23beaa)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x368d4016)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1c75408f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x76f38aa9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x318c6e8d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19593854)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x64cb1d30)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4eb18ce9)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1ab4e27d)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x61b598cc)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1af33106)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x740e8376)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35c2a9e3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5edccd6)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5d612fd3)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x5c0576b2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x73d1802f)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x35043a2e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6cc8ddb)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x735eed9e)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x3f48b6a2)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x19413805)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x748e9998)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x1bdc98f0)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4e53a8ef)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x6061cbd5)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x4a31592)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x39d97998)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0xa42d4da)
		ret = TC_ACT_SHOT;
	else if(src_ip == 0x26613b5c)
		ret = TC_ACT_SHOT;
	return ret;
}

char license[] __section("license") = "GPL";

