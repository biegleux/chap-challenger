/*
 * chap-challenger v0.2 - send spoofed chap challenges in pppoe frames
 *
 * Copyright (c) 2008-2010, Tibor Bombiak
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

#include <net/ethernet.h>

/* Length of Protocol Field in PPP frame */
#define PPP_PROTOLEN		2

/* Maximum number of concurrently registered stations */
#define MAX_STA_COUNT		2007
/* maximum length buffer required */
#define BUF_MAXLEN		sizeof(uint) + MAX_STA_COUNT * sizeof(struct ether_addr)

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_SESSION	0x8864

/* PPPoE codes */
#define CODE_SESS		0x00

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD		6  /* type, code, session, length */
#define PPPOE_HEADERLEN		(sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD	(ETH_DATA_LEN - PPPOE_OVERHEAD)
#define MAX_PPPOE_MTU		(MAX_PPPOE_PAYLOAD - 2)

#define CHAP_HEADERLEN		4	/* CODE + ID + Length */

#define CHAP_CHALLENGE		1
#define CHAP_RESPONSE		2
#define CHAP_SUCCESS		3
#define CHAP_FAILURE    	4

#define MAX_NAME_LEN		255
/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */

#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}

#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}

#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}

#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

/* A PPPoE Packet, including Ethernet headers */
typedef struct PPPoEPacketStruct {
    struct ethhdr ethHdr;	/* Ethernet header */
    unsigned int type:4;	/* PPPoE Type (must be 1) */
    unsigned int ver:4;		/* PPPoE Version (must be 1) */
    unsigned int code:8;	/* PPPoE code */
    unsigned int session:16;	/* PPPoE session */
    unsigned int length:16;	/* Payload length */
    unsigned char payload[MAX_PPPOE_PAYLOAD]; /* A bit of room to spare */
} PPPoEPacket;

struct maclist {
	uint count;			/* number of MAC addresses */
	struct ether_addr ea[1];	/* variable length array of MAC addresses */
};

#define I_FLG	0x01
#define A_FLG	0x02
#define B_OFF	0x00
#define B_ON	0x01

#define SETFLAG(x, flg)	((x) |= 0x01 << (flg))
#define GETFLAG(x, flg)	(((x) >> (flg)) & 0x01)

#define VERSION "0.2"
