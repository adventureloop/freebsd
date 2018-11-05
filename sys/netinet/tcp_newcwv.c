/*
 * Copyright (c) 2014 Tom Jones <jones@sdf.org>
 * All rights reserved.
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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_newcwv.h>

/*
 * An implementation of NewCWV (draft-ietf-tcpm-newcwv-10) for FreeBSD.
 * Based on the Linux implementation by Raffaello Secchi and the an initial
 * implementation of draft-ietf-tcpm-newcwv-00 by Aris Angelogiannopoulos.
 */

#define nextbin(x) (((x)+1) & 0x03)
#define prevbin(x) (((x)-1) & 0x03)

#define NCWV_UNDEF 0xFFFFFFFF
#define NCWV_FIVEMINS (300*hz)

void add_element(struct tcpcb *,u_int32_t);
u_int32_t remove_expired_elements(struct tcpcb *);

void
tcp_newcwv_update_pipeack(struct tcpcb *tp)
{
	u_int32_t tmp_pipeack;
	tp->newcwv.psp = MAX(3 * tp->t_srtt,hz); 

	if (tp->snd_una >= tp->newcwv.prev_snd_nxt) {
		/* get the pipeack sample */
		tmp_pipeack = tp->snd_una - tp->newcwv.prev_snd_una;

		tp->newcwv.prev_snd_una = tp->snd_una;
		tp->newcwv.prev_snd_nxt = tp->snd_nxt;

		/* create a new element at the end of current pmp */
		if(ticks > tp->newcwv.time_stamp[tp->newcwv.head] + 
			(tp->newcwv.psp >> 2)) 
			add_element(tp,tmp_pipeack);
		else 
			tp->newcwv.psample[tp->newcwv.head] = tmp_pipeack;
	}

	tp->newcwv.pipeack = remove_expired_elements(tp);

	/* check if cwnd is validated */
	if (tp->newcwv.pipeack == NCWV_UNDEF || 
		((tp->newcwv.pipeack << 1) >= (tp->snd_cwnd * tp->t_maxseg))) {
		tp->newcwv.cwnd_valid_ts = ticks;
	} 
}

void 
add_element(struct tcpcb *tp,u_int32_t value)
{
	tp->newcwv.head = nextbin(tp->newcwv.head);
	tp->newcwv.psample[tp->newcwv.head] = value;
	tp->newcwv.time_stamp[tp->newcwv.head] = ticks;
}

u_int32_t
remove_expired_elements(struct tcpcb *tp)
{
	uint8_t head = tp->newcwv.head;
	u_int32_t tmp = tp->newcwv.psample[head];

	while(tp->newcwv.psample[head] != NCWV_UNDEF) {
		/* remove the element if expired */
		if (tp->newcwv.time_stamp[head] < ticks - tp->newcwv.psp) {
			tp->newcwv.psample[head] = NCWV_UNDEF;
			return tmp;
		}

		/* search for the max pipeack */
		if(tp->newcwv.psample[head] > tmp)
			tmp = tp->newcwv.psample[head];

		head = prevbin(head);
		if(head == tp->newcwv.head)
			return tmp;
	}	

	return tmp;
}

/* Initialise NewCWV state */
void
tcp_newcwv_reset(struct tcpcb *tp)
{
	tp->newcwv.prev_snd_una = tp->snd_una;
	tp->newcwv.prev_snd_nxt = tp->snd_nxt;
	tp->newcwv.cwnd_valid_ts = ticks;
	tp->newcwv.loss_flight_size = 0;

	tp->newcwv.head = 0;
	tp->newcwv.psample[0] = NCWV_UNDEF;
	tp->newcwv.pipeack = NCWV_UNDEF;
}

/* NewCWV actions at loss detection */
void
tcp_newcwv_enter_recovery(struct tcpcb *tp)
{
	u_int32_t pipe;

	if(tp->newcwv.pipeack == NCWV_UNDEF)
		return;

	tp->newcwv.prior_retrans = tp->t_sndrexmitpack;

	/* Calculate the flight size */
	u_int32_t awnd = (tp->snd_nxt - tp->snd_fack) + tp->sackhint.sack_bytes_rexmit;
	tp->newcwv.loss_flight_size = awnd;

	pipe = MAX(tp->newcwv.pipeack,tp->newcwv.loss_flight_size);
	tp->snd_cwnd = MAX(pipe >> 1,1);
}

/* NewCWV actions at the end of recovery */
void
tcp_newcwv_end_recovery(struct tcpcb *tp)
{
	u_int32_t retrans,pipe;

	retrans = (tp->t_sndrexmitpack - tp->newcwv.prior_retrans) * tp->t_maxseg;
	pipe = MAX(tp->newcwv.pipeack,tp->newcwv.loss_flight_size) - retrans;

	/* Ensure that snd_ssthresh is non 0 */
	tp->snd_ssthresh = MAX(pipe >> 1,1); 
	tp->snd_cwnd = tp->snd_ssthresh;
}

void
tcp_newcwv_datalim_closedown(struct tcpcb *tp)
{
	while ((ticks - tp->newcwv.cwnd_valid_ts) > NCWV_FIVEMINS && 
	  tp->snd_cwnd > tp->newcwv.init_cwnd) {

		tp->newcwv.cwnd_valid_ts += NCWV_FIVEMINS;
		tp->snd_ssthresh = MAX( (3 * tp->snd_cwnd ) >> 2,tp->snd_ssthresh);
		tp->snd_cwnd = MAX(tp->snd_cwnd >> 1, tp->newcwv.init_cwnd);
	}
}
