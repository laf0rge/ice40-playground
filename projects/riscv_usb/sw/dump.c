/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/isdnhdlc.h>
#include <osmocom/abis/lapd_pcap.h>

#define E1_CHUNK_HDR_MAGIC	0xe115600d /* E1 is good */
struct e1_chunk_hdr {
	uint32_t magic;
	struct {
		uint64_t sec;
		uint64_t usec;
	} time;
	uint16_t len;		/* length of following payload */
	uint8_t ep;		/* USB endpoint */
} __attribute__((packed));

static struct osmo_isdnhdlc_vars g_hdlc[2]; /* one per direction */
static int g_pcap_fd = -1;
static struct msgb *g_pcap_msg;

/* called for each HDLC payload frame */
static void handle_payload(uint8_t ep, const uint8_t *data, int len)
{
	int dir;

	switch (ep) {
	case 0x81:
		dir = OSMO_LAPD_PCAP_INPUT;
		break;
	case 0x82:
		dir = OSMO_LAPD_PCAP_OUTPUT;
		break;
	default:
		fprintf(stderr, "Unexpected USB EP 0x%02x\n", ep);
		return;
	}

	if (g_pcap_fd >= 0) {
		uint8_t *cur = msgb_put(g_pcap_msg, len);
		memcpy(cur, data, len);
		osmo_pcap_lapd_write(g_pcap_fd, dir, g_pcap_msg);
		msgb_reset(g_pcap_msg);
	} else
		printf("OUT[%02x]: %s\n", ep, osmo_hexdump(data, len));
}


/* called for each USB transfer read from the file */
static void handle_frame(const struct e1_chunk_hdr *hdr, const uint8_t *data)
{
	uint8_t nots0[1024];
	unsigned int offs = 0;
	struct osmo_isdnhdlc_vars *hdlc;

	/* filter on the endpoint (direction) specified by the user */
	switch (hdr->ep) {
	case 0x81:
		hdlc = &g_hdlc[0];
		break;
	case 0x82:
		hdlc = &g_hdlc[1];
		break;
	default:
		fprintf(stderr, "Unexpected USB EP 0x%02x\n", hdr->ep);
		return;
	}

	if (hdr->len <= 4)
		return;

	for (int i = 4; i < hdr->len-4; i += 32) {
		//printf("\t%s\n", osmo_hexdump(data+i, 32));
		memcpy(nots0+offs, data+i+1, 32-1);
		offs += 31;
	}

	//printf("IN: %s\n", osmo_hexdump(nots0, offs));
	uint8_t out[512];
	int rc;
	int rl;

	int oi = 0;

	while (oi < offs) {
		rc = osmo_isdnhdlc_decode(hdlc, nots0+oi, offs-oi, &rl, out, sizeof(out));
		if (rc < 0)
			fprintf(stderr, "ERR in HDLC decode: %d\n", rc);
		else if (rc > 0)
			handle_payload(hdr->ep, out, rc);
		oi += rl;
	}
}

static int process_file(int fd)
{
	struct e1_chunk_hdr hdr;
	unsigned long offset = 0;
	uint8_t buf[65535];
	int rc;

	while (1) {
		memset(buf, 0, sizeof(buf));
		/* first read header */
		rc = read(fd, &hdr, sizeof(hdr));
		if (rc < 0)
			return rc;
		if (rc != sizeof(hdr)) {
			fprintf(stderr, "%d is less than header size (%zd)\n", rc, sizeof(hdr));
			return -1;
		}
		offset += rc;
		if (hdr.magic != E1_CHUNK_HDR_MAGIC) {
			fprintf(stderr, "offset %lu: Wrong magic 0x%08x\n", offset, hdr.magic);
			return -1;
		}

		/* then read payload */
		rc = read(fd, buf, hdr.len);
		if (rc < 0)
			return rc;
		offset += rc;
		if (rc != hdr.len) {
			fprintf(stderr, "%d is less than payload size (%d)\n", rc, hdr.len);
			return -1;
		}
		handle_frame(&hdr, buf);
	}
}

static int open_file(const char *fname)
{
	return open(fname, O_RDONLY);
}


static const struct log_info_cat log_categories[] = {
};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	char *fname;
	int rc;
	int i;

	osmo_init_logging2(NULL, &log_info);

	if (argc < 2) {
		fprintf(stderr, "You must specify the file name of the ICE40-E1 capture\n");
		exit(1);
	}
	fname = argv[1];

	rc = open_file(fname);
	if (rc < 0) {
		fprintf(stderr, "Error opening %s: %s\n", fname, strerror(errno));
		exit(1);
	}

	if (argc >= 3) {
		g_pcap_fd = osmo_pcap_lapd_open(argv[2], 0640);
		if (g_pcap_fd < 0) {
			fprintf(stderr, "Unable to open PCAP output: %s\n", strerror(errno));
			exit(1);
		}
		g_pcap_msg = msgb_alloc(4096, "pcap");
	}

	for (i = 0; i < ARRAY_SIZE(g_hdlc); i++)
		osmo_isdnhdlc_rcv_init(&g_hdlc[i], OSMO_HDLC_F_BITREVERSE);

	process_file(rc);
}
