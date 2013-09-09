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
#include <net/inet_common.h>

#include "common.h"
#include "log.h"
#include "sock.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Linux Kernel Synchronous Sockets");
MODULE_VERSION("0.1.1");
MODULE_LICENSE("GPL");

static SsHooks *ss_hooks __read_mostly;

#define SS_CALL(f, ...)		(ss_hooks->f ? ss_hooks->f(__VA_ARGS__) : 0)

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

	SS_DBG("%s:%d is_queue_empty=%d tcp_send_head(sk)=%p sk->sk_state=%d\n",
	       __FUNCTION__, __LINE__, tcp_write_queue_empty(sk),
	       tcp_send_head(sk), sk->sk_state);

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
		SS_CALL(postpone_skb, proto, skb);
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

	/* Process linear data. */
	if (off < lin_len) {
		SS_CALL(put_skb_to_msg, proto, skb);

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
			unsigned char *vaddr = kmap_atomic(skb_frag_page(frag));

			SS_CALL(put_skb_to_msg, proto, skb);

			r = ss_tcp_process_proto_skb(proto, vaddr + off,
						     f_sz - off, skb);

			kunmap_atomic(vaddr);

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

static void
ss_tcp_close(struct sock *sk)
{
	SS_CALL(connection_drop, sk);
#if 0
	if (sk->sk_destruct) {
		sk->sk_destruct(sk);
		/* Don't call the destructor any more from Lunux TCP calls. */
		sk->sk_destruct = NULL;
	}
#endif
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

	r = SS_CALL(connection_recv, sk);
	if (r) {
		ss_tcp_close(sk);
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
		ss_tcp_close(sk);
	}

	return r;
}

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 * Called under bh_lock_sock_nested(sk).
 *
 * We can't use standard tcp_read_sock() with our actor callback, because
 * tcp_read_sock() calls __kfree_skb() through sk_eat_skb() which is good
 * for copying data from skb, but we need to manage skb's ourselves.
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
			return;
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
				SS_WARN("DROP blocked skb");
				goto out; /* connection dropped */
			}
			tp->copied_seq += count;
			processed += count;
			/*
			 * TODO currently we free the skb,
			 * but we shouldn't do this if it's postponed.
			 */
			__kfree_skb(skb);
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
	 * Recalculate the appropriate TCP receive buffer space and
	 * send ACK to the client with new window.
	 */
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);
}

/**
 * Just drain accept queue of listening socket &lsk.
 * See implementation of standard inet_csk_accept().
 */
static void
ss_drain_accept_queue(struct sock *lsk, struct sock *nsk)
{
	struct inet_connection_sock *icsk = inet_csk(lsk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *prev_r, *req;

	/* Currently we process TCP only. */
	BUG_ON(lsk->sk_protocol != IPPROTO_TCP);

	WARN(reqsk_queue_empty(queue),
	     "drain empty accept queue for socket %p", lsk);

#if 0
	/* TODO it works to slowly, need to patch Linux kernel to make it faster. */
	for (prev_r = NULL, req = queue->rskq_accept_head; req;
	     prev_r = req, req = req->dl_next)
	{
		if (req->sk != nsk)
			continue;
		/* We found the socket, remove it. */
		if (prev_r) {
			/* There are some items before @req in the queue. */
			prev_r->dl_next = req->dl_next;
			if (queue->rskq_accept_tail == req)
				/* @req is the last item. */
				queue->rskq_accept_tail = prev_r;
		} else {
			/* @req is the first item in the queue. */
			queue->rskq_accept_head = req->dl_next;
			if (queue->rskq_accept_head == NULL)
				/* The queue contained only this one item. */
				queue->rskq_accept_tail = NULL;
		}
		break;
	}
#else
	/*
	 * FIXME push any request from the queue,
	 * doesn't matter which exactly.
	 */
	req = reqsk_queue_remove(queue);
#endif
	BUG_ON(!req);
	sk_acceptq_removed(lsk);

	/*
	 * @nsk is in ESTABLISHED state, so 3WHS has completed and
	 * we can safely remove the request socket from accept queue of @lsk.
	 */
	__reqsk_free(req);
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
/*
 * Called when a new data received on the socket.
 *
 * XXX ./net/ipv4/tcp_* call sk_data_ready() with 0 as the value of @bytes.
 * This seems wrong.
 */
static void
ss_tcp_data_ready(struct sock *sk, int bytes)
{
	int processed = 0;

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

/**
 * Socket failover.
 */
static void
ss_tcp_error(struct sock *sk)
{
	SS_DBG("process error on socket %p\n", sk);

	write_lock_bh(&sk->sk_callback_lock);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);

	write_unlock_bh(&sk->sk_callback_lock);
}

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);

	if (sk->sk_state == TCP_ESTABLISHED) {
		SsProto *proto = sk->sk_user_data;
		struct sock *lsk = proto->listener;
		BUG_ON(!lsk);

		/* The callback is called from tcp_rcv_state_process(). */
		SS_CALL(connection_new, sk);

		/* Set socket callbask for new data socket. */
		sk->sk_data_ready = ss_tcp_data_ready;
		sk->sk_state_change = ss_tcp_state_change;
		sk->sk_error_report = ss_tcp_error;

		/*
		 * We know which socket is just accepted, so we just
		 * drain listening socket accept queue and don't care
		 * about returned socket.
		 */
		assert_spin_locked(&lsk->sk_lock.slock);
		ss_drain_accept_queue(lsk, sk);
	}
	else if (sk->sk_state == TCP_CLOSE_WAIT) {
		/*
		 * Connection has received FIN.
		 *
		 * FIXME it seems we should to do things below on TCP_CLOSE
		 * instead of TCP_CLOSE_WAIT.
		 */
		SS_DBG("connection closed on socket %p\n", sk);
		ss_tcp_close(sk);
	}

	write_unlock_bh(&sk->sk_callback_lock);
}

void
ss_tcp_set_listen(struct sock *sk, SsProto *handler)
{
	write_lock_bh(&sk->sk_callback_lock);

	BUG_ON(sk->sk_user_data);

	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_user_data = handler;
	handler->listener = sk;

	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_tcp_set_listen);

/**
 * Just a dummy and ugly wrapper for inet_release().
 */
void
ss_sock_release(struct sock *sk)
{
	struct socket sock = { .sk = sk };
	inet_release(&sock);
}
EXPORT_SYMBOL(ss_sock_release);

/*
 * ------------------------------------------------------------------------
 *  	Sockets initialization
 * ------------------------------------------------------------------------
 */

/*
 * FIXME Only one user for now, don't care about registration races.
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
