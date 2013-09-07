/**
 * Synchronous Socket API.
 *
 * Server and client socket (connecton) definitions.
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
#ifndef __SS_SOCK_H__
#define __SS_SOCK_H__

#include <linux/skbuff.h>

#include "proto.h"

/* Table of socket connection callbacks. */
typedef struct {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/* Drop TCP connection associated with the socket. */
	int (*connection_drop)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(struct sock *sk);

	/*
	 * Add the @skb to the current connection message.
	 * We need this low-level sk_buff opertation at connection (higher)
	 * level to provide zero-copy with socket buffers reusage.
	 */
	int (*put_skb_to_msg)(SsProto *proto, struct sk_buff *skb);

	/*
	 * Postpone the @skb into internal protocol queue.
	 */
	int (*postpone_skb)(SsProto *proto, struct sk_buff *skb);
} SsHooks;

int ss_hooks_register(SsHooks* hooks);
void ss_hooks_unregister(SsHooks* hooks);

void ss_send(struct sock *sk, struct sk_buff_head *skb_list, int len);

/* TCP socket callbacks. */
void ss_tcp_set_listen(struct sock *sk, SsProto *handler);

#endif /* __SS_SOCK_H__ */
