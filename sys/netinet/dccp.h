/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Tom Jones <thj@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#ifndef _NETINET_DCCP_H_
#define _NETINET_DCCP_H_

__FBSDID("$FreeBSD$");

/* DCCP protocol header as per RFC4340 */
struct dccphdr {
	uint16_t	d_sport;
	uint16_t	d_dport;
	uint8_t		d_doff;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t		d_cscov:4,
			d_ccval:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		d_ccval:4,
			d_cscov:4;
#endif
	uint16_t	d_cksum;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t		d_res:3,
			d_type:4,
			d_x:1;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t		d_x:1,
			d_type:4,
			d_res:3;
#endif
	uint8_t		d_seq[6];
};

#define DCCP_SHORTHDR	12
#define DCCP_LONGHDR	16
#define DCCP_EXTHDR	0x80

#endif /* _NETINET_DCCP_H */
