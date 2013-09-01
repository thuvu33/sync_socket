/**
 * Synchronous Socket API.
 *
 * Generic socket routines.
 *
 * Copyright (C) 2012-2013 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * TODO:
 * -- Read cache objects by 64KB and use GSO?
 */
#include <linux/highmem.h>
#include <linux/module.h>
#include <net/tcp.h>

#include "common.h"
#include "log.h"
#include "sock.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Linux Kernel Synchronous Sockets");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

static SsHooks *ss_hooks __read_mostly;

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * Directly insert all skbs from @skb_list into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying.
 * See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Called in softirq context.
 *
 * TODO use MSG_MORE untill we reach end of message.
 */
void
ss_send(struct sock *sk, struct sk_buff_head *skb_list, int len)
{
	struct sk_buff *skb;
	struct tcp_skb_cb *tcb;
	struct tcp_sock *tp = tcp_sk(sk);
	int flags = MSG_DONTWAIT; /* we can't sleep */
	int size_goal, mss_now;

	mss_now = tcp_send_mss(sk, &size_goal, flags);

	BUG_ON(skb_queue_empty(skb_list));
	for (skb = skb_peek(skb_list), tcb = TCP_SKB_CB(skb);
	     skb; skb = skb_peek(skb_list))
	{
		skb_unlink(skb, skb_list);

		skb_entail(sk, skb);
		/*
		 * TODO
		 * Mark all data with PUSH to force receiver to consume
		 * the data. Currently we do this in debugging purpose.
		 * We need to do this only for complete messages.
		 */
		tcp_mark_push(tp, skb);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_shinfo(skb)->gso_segs = 0;
	}

	tcb->end_seq += len;
	tp->write_seq += len;

	SS_DBG("%s:%d tp->early_retrans_delayed=%d is_queue_empty=%d"
	       " tcp_send_head(sk)=%p sk->sk_state=%d\n",
	       __FUNCTION__, __LINE__, tp->early_retrans_delayed,
	       tcp_write_queue_empty(sk), tcp_send_head(sk), sk->sk_state);

	tcp_push(sk, flags, mss_now, TCP_NAGLE_OFF|TCP_NAGLE_PUSH);
}
EXPORT_SYMBOL(ss_send);

static int
ss_tcp_process_proto_skb(SsProto *proto, unsigned char *data, size_t len,
			 struct sk_buff *skb)
{
	int r = ss_proto_run_handlers(proto, data, len);
	if (unlikely(r))
		return r;

	if (r == SS_POSTPONE) {
		if (ss_hooks->postpone_skb)
			ss_hooks->postpone_skb(proto, skb);
		r = SS_OK;
	}

	return r;
}

/**
 * Process a socket buffer.
 * See standard skb_copy_datagram_iovec() implementation.
 * @return SS_OK, SS_DROP or negative value of error code.
 */
static int
ss_tcp_process_skb(struct sk_buff *skb, struct sock *sk, unsigned int off,
		   SsProto *proto, int *count)
{
	int i, r = SS_OK;
	int lin_len = skb_headlen(skb);
	struct sk_buff *frag_i;

	BUG_ON(!ss_hooks->put_skb_to_msg);

	/* Process linear data. */
	if (off < lin_len) {
		ss_hooks->put_skb_to_msg(proto, skb);

		r = ss_tcp_process_proto_skb(proto, skb->data + off,
					     lin_len - off, skb);
		if (r < 0 || r == SS_DROP)
			return r;
		*count += lin_len - off;
		off = 0;
	} else
		off -= lin_len;

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int f_sz = skb_frag_size(frag);
		if (f_sz > off) {
			struct page *page = skb_frag_page(frag);
			unsigned char *vaddr = kmap(page);

			ss_hooks->put_skb_to_msg(proto, skb);

			r = ss_tcp_process_proto_skb(proto, vaddr + off,
						     f_sz - off, skb);

			kunmap(page);
			if (r < 0 || r == SS_DROP)
				return r;
			*count += f_sz - off;
			off = 0;
		} else
			off -= f_sz;
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		if (frag_i->len > off) {
			r = ss_tcp_process_skb(frag_i, sk, off, proto, count);
			if (r < 0)
				return r;
			off = 0;
		} else
			off -= frag_i->len;
	}

	return r;
}

/**
 * Process received data on the socket.
 * @return SS_OK, SS_DROP or negative value of error code.
 *
 * TODO One connection MUST be processed on one CPU - ensure this.
 */
static int
ss_tcp_process_connection(struct sk_buff *skb, struct sock *sk,
			  unsigned int off, int *count)
{
	int r;
	SsProto *proto = sk->sk_user_data;

	BUG_ON(!ss_hooks->connection_recv);
	BUG_ON(!ss_hooks->connection_drop);

	r = ss_hooks->connection_recv(sk);
	if (r) {
		ss_hooks->connection_drop(sk);
		return r;
	}

	r = ss_tcp_process_skb(skb, sk, off, proto, count);
	if (r < 0 || r == SS_DROP) {
		if (r < 0)
			SS_WARN("can't process app data on socket %p\n", sk);
		/*
		 * Drop connection on internal errors as well as
		 * on banned packets.
		 */
		ss_hooks->connection_drop(sk);
	}

	return r;
}

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 * Called under bh_lock_sock_nested(sk).
 *
 * TODO:
 * -- process URG
 */
static void
ss_tcp_process_data(struct sock *sk)
{
	int processed = 0;
	unsigned int off;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("recvmsg bug: TCP sequence gap at seq %X"
				" recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			/* TODO drop the connection */
			goto out;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);

		off = tp->copied_seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			off--;
		if (off < skb->len) {
			int count = 0;
			int r = ss_tcp_process_connection(skb, sk, off, &count);
			if (r < 0 || r == SS_DROP) {
				__kfree_skb(skb);
				return; /* connection dropped */
			}
			tp->copied_seq += count;
			processed += count;
		}
		else if (tcp_hdr(skb)->fin) {
			++tp->copied_seq;
			/* TODO close the connection */
			__kfree_skb(skb);
		}
		else {
			SS_WARN("recvmsg bug: overlapping TCP segment at %X"
				" seq %X rcvnxt %X len %x\n",
			       tp->copied_seq, TCP_SKB_CB(skb)->seq,
			       tp->rcv_nxt, skb->len);
			__kfree_skb(skb);
		}
	}
out:
	/*
	 * Send ACK to the client and recalculate the appropriate TCP receive
	 * buffer space.
	 */
	tcp_cleanup_rbuf(sk, processed);
	tcp_rcv_space_adjust(sk);
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
/*
 * Called when a new data received on the socket.
 */
void
ss_tcp_data_ready(struct sock *sk, int bytes)
{
	if (!skb_queue_empty(&sk->sk_error_queue)) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		SS_ERR("error data on socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		ss_tcp_process_data(sk);
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in th_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			SS_DBG("urgent data on socket %p\n", sk);
		}
	}
}
EXPORT_SYMBOL(ss_tcp_data_ready);

/**
 * Socket state change callback.
 */
void
ss_tcp_state_change(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		BUG_ON(!ss_hooks->connection_new);

		ss_hooks->connection_new(sk);
	}
	else if (sk->sk_state == TCP_CLOSE_WAIT) {
		/* Connection has closed. */
		SS_DBG("connection closed on socket %p\n", sk);

		if (sk->sk_destruct)
			sk->sk_destruct(sk);
	}
}
EXPORT_SYMBOL(ss_tcp_state_change);

/**
 * Socket failover.
 */
void
ss_tcp_error(struct sock *sk)
{
	SS_DBG("process error on socket %p\n", sk);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);
}
EXPORT_SYMBOL(ss_tcp_error);

/*
 * ------------------------------------------------------------------------
 *  	Sockets initialization
 * ------------------------------------------------------------------------
 */

/*
 * Only one user for now, don't care about registration races.
 */
int
ss_hooks_register(SsHooks* hooks)
{
	if (ss_hooks)
		return -EEXIST;

	ss_hooks = hooks;

	return 0;
}
EXPORT_SYMBOL(ss_hooks_register);

void
ss_hooks_unregister(SsHooks* hooks)
{
	BUG_ON(hooks != ss_hooks);
	ss_hooks = NULL;
}
EXPORT_SYMBOL(ss_hooks_unregister);

int __init
ss_init(void)
{
	return 0;
}

void __exit
ss_exit(void)
{
}

module_init(ss_init);
module_exit(ss_exit);
