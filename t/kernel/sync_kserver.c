/**
 * Multiplexing kernel server using synchronous sockets for performance testing
 * of Synchronous Socket API.
 *
 * It works fully in softirq context as opposed to kserver working mostly in
 * kworker threads.
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
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/inet_sock.h>

#include "../../sock.h"

#define MAX_CONN	(1000 * 1000)
#define PORT		5000

/* Application logic class inherited from SsProto. */
typedef struct {
	SsProto		proto;
} MyProto;

static struct socket *listen_sock;
static MyProto my_proto;

/* Statistics */
static long last_ts = 0;
static unsigned int pps_curr = 0, pps_max = 0;
static DEFINE_SPINLOCK(stat_lock);

static int g_counter;

static atomic_t conn_i = ATOMIC_INIT(0);
static struct socket *conn[MAX_CONN] = { NULL };

MODULE_LICENSE("GPL");

static void
stat_update(void)
{
	spin_lock(&stat_lock);
	if (last_ts == jiffies / HZ) {
		pps_curr++;
	} else {
		// recahrge
		if (pps_curr > pps_max)
			pps_max = pps_curr;
		pps_curr = 1;
		last_ts = jiffies / HZ;
	}
	spin_unlock(&stat_lock);
}

void
stat_print(void)
{
	printk(KERN_ERR "Best rps: %u\n",
	       pps_curr > pps_max ? pps_curr : pps_max);
}

/*
 * Just do some useless work.
 */
static int
kserver_read(void *proto, unsigned char *data, size_t len)
{
	int i;
	for (i = 0; i < len / 4; ++i)
		g_counter += data[i];

	stat_update();

	return 0;
}

static int
kserver_connection_new(struct sock *sock)
{
	int ci;

	BUG_ON(!sock->sk_user_data);

	/* TODO Typically we should allocate a new connection here. */

	/* Write the socket to free it as module exit. */
	ci = atomic_inc_return(&conn_i);
	if (ci < MAX_CONN) {
		conn[ci] = sock->sk_socket;
	} else {
		printk(KERN_ERR "Too many connections!\n");
	}

	return 0;
}

static int
kserver_connection_drop(struct sock *sk)
{
	stat_update();

	return 0;
}

static SsHooks ssocket_hooks = {
	.connection_new		= kserver_connection_new,
	.connection_drop	= kserver_connection_drop,
};

int __init
kserver_init(void)
{
	int r;
	struct sockaddr_in saddr;

	r = ss_hooks_register(&ssocket_hooks);
	if (r) {
		printk(KERN_ERR "Can't register synchronous socket callbacks\n");
		return r;
	}

	r = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_sock);
	if (r) {
		printk(KERN_ERR "Can't listening socket\n");
		goto err_create;
	}

	inet_sk(listen_sock->sk)->freebind = 1;
	listen_sock->sk->sk_reuse = 1;

	/* Register application logic stack for the socket. */
	ss_proto_push_handler((SsProto *)&my_proto, kserver_read);
	/* Set TCP handlers. */
	ss_tcp_set_listen(listen_sock->sk, (SsProto *)&my_proto);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

	r = listen_sock->ops->bind(listen_sock, (struct sockaddr *)&saddr,
				   sizeof(saddr));
	if (r) {
		printk(KERN_ERR "Can't bind listening socket\n");
		goto err_call;
	}

	r = listen_sock->ops->listen(listen_sock, 1000);
	if (r) {
		printk(KERN_ERR "Can't listen on socket\n");
		goto err_call;
	}

	return 0;
err_call:
	sock_release(listen_sock);
err_create:
	ss_hooks_unregister(&ssocket_hooks);
	return r;
}

void __exit
kserver_exit(void)
{
	int ci;

	sock_release(listen_sock);
	for (ci = 0; ci < atomic_read(&conn_i); ++ci)
		if (conn[ci])
			sock_release(conn[ci]);

	stat_print();
}

module_init(kserver_init);
module_exit(kserver_exit);
