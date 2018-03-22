/*
 * ipfou.c	FOU (foo over UDP) support
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Tom Herbert <therbert@google.com>
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/fou.h>
#include <linux/genetlink.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ip fou add port PORT "
		"{ ipproto PROTO  | gue } [ -6 ]\n");
	fprintf(stderr, "       ip fou del port PORT [ -6 ]\n");
	fprintf(stderr, "       ip fou show\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where: PROTO { ipproto-name | 1..255 }\n");
	fprintf(stderr, "       PORT { 1..65535 }\n");

	exit(-1);
}

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define FOU_REQUEST(_req, _bufsiz, _cmd, _flags)	\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,	\
		     FOU_GENL_VERSION, _cmd, _flags)

static int fou_parse_opt(int argc, char **argv, struct nlmsghdr *n,
			 bool adding)
{
	__u16 port;
	int port_set = 0;
	__u8 ipproto, type;
	bool gue_set = false;
	int ipproto_set = 0;
	__u8 family = AF_INET;

	while (argc > 0) {
		if (!matches(*argv, "port")) {
			NEXT_ARG();

			if (get_be16(&port, *argv, 0) || port == 0)
				invarg("invalid port", *argv);
			port_set = 1;
		} else if (!matches(*argv, "ipproto")) {
			struct protoent *servptr;

			NEXT_ARG();

			servptr = getprotobyname(*argv);
			if (servptr)
				ipproto = servptr->p_proto;
			else if (get_u8(&ipproto, *argv, 0) || ipproto == 0)
				invarg("invalid ipproto", *argv);
			ipproto_set = 1;
		} else if (!matches(*argv, "gue")) {
			gue_set = true;
		} else if (!matches(*argv, "-6")) {
			family = AF_INET6;
		} else {
			fprintf(stderr, "fou: unknown command \"%s\"?\n", *argv);
			usage();
			return -1;
		}
		argc--, argv++;
	}

	if (!port_set) {
		fprintf(stderr, "fou: missing port\n");
		return -1;
	}

	if (!ipproto_set && !gue_set && adding) {
		fprintf(stderr, "fou: must set ipproto or gue\n");
		return -1;
	}

	if (ipproto_set && gue_set) {
		fprintf(stderr, "fou: cannot set ipproto and gue\n");
		return -1;
	}

	type = gue_set ? FOU_ENCAP_GUE : FOU_ENCAP_DIRECT;

	addattr16(n, 1024, FOU_ATTR_PORT, port);
	addattr8(n, 1024, FOU_ATTR_TYPE, type);
	addattr8(n, 1024, FOU_ATTR_AF, family);

	if (ipproto_set)
		addattr8(n, 1024, FOU_ATTR_IPPROTO, ipproto);

	return 0;
}

static int do_add(int argc, char **argv)
{
	FOU_REQUEST(req, 1024, FOU_CMD_ADD, NLM_F_REQUEST);

	fou_parse_opt(argc, argv, &req.n, true);

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0)
		return -2;

	return 0;
}

static int do_del(int argc, char **argv)
{
	FOU_REQUEST(req, 1024, FOU_CMD_DEL, NLM_F_REQUEST);

	fou_parse_opt(argc, argv, &req.n, false);

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0)
		return -2;

	return 0;
}

static int print_fou_mapping(const struct sockaddr_nl *who,
				 struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct genlmsghdr *ghdr;
	struct rtattr *tb[FOU_ATTR_MAX + 1];
	int len = n->nlmsg_len;
	unsigned family;

	if (n->nlmsg_type != genl_family)
		return 0;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);
	parse_rtattr(tb, FOU_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (tb[FOU_ATTR_PORT])
		fprintf(fp, "port %u", ntohs(rta_getattr_u16(tb[FOU_ATTR_PORT])));
	if (tb[FOU_ATTR_TYPE] && rta_getattr_u8(tb[FOU_ATTR_TYPE]) == FOU_ENCAP_GUE)
		fprintf(fp, " gue");
	else if (tb[FOU_ATTR_IPPROTO])
		fprintf(fp, " ipproto %u", rta_getattr_u8(tb[FOU_ATTR_IPPROTO]));
	if (tb[FOU_ATTR_AF]) {
		family = rta_getattr_u8(tb[FOU_ATTR_AF]);
		if (family == AF_INET6)
			fprintf(fp, " -6");
	}
	fprintf(fp, "\n");

	return 0;
}

static int do_show(int argc, char **argv)
{
	FOU_REQUEST(req, 4096, FOU_CMD_GET, NLM_F_REQUEST | NLM_F_DUMP);

	if (argc > 0) {
		fprintf(stderr, "\"ip fou show\" does not take any arguments.\n");
		return -1;
	}

	if (rtnl_send(&genl_rth, &req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send show request");
		exit(1);
	}

	if (rtnl_dump_filter(&genl_rth, print_fou_mapping, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}

	return 0;
}

int do_ipfou(int argc, char **argv)
{
	if (argc < 1)
		usage();

	if (matches(*argv, "help") == 0)
		usage();

	if (genl_init_handle(&genl_rth, FOU_GENL_NAME, &genl_family))
		exit(1);

	if (matches(*argv, "add") == 0)
		return do_add(argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return do_del(argc-1, argv+1);
	if (matches(*argv, "show") == 0)
		return do_show(argc-1, argv+1);
	fprintf(stderr, "Command \"%s\" is unknown, try \"ip fou help\".\n", *argv);
	exit(-1);
}
