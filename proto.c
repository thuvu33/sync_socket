/**
 * Synchronous Socket API.
 *
 * Generic protocols handling for session, presentation and application
 * (l5-l7) levels.
 *
 * Only one protocol (HTTP) family is currently supported, so all the handlers
 * are called unconditionaly. If other protoclols are added, then calling and
 * registering routines must be reworked to be port and type of transport
 * protocol aware.
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
#include <linux/module.h>

#include "common.h"
#include "proto.h"

/**
 * Execute all l5-l7 protocol handlers.
 * @return number of processed bytes at session (l5) level or error code.
 */
int
ss_proto_run_handlers(SsProto *proto, unsigned char *data, size_t len)
{
	int i, ret = SS_OK;

	for (i = 0; i < SS_MAX_PROTO_STACK_N && proto->handlers[i]; ++i) {
		int r = proto->handlers[i](proto, data, len);
		if (unlikely(r < 0))
			/* An error occured, don't run rest of callbacks. */
			return r;
		switch (r) {
		case SS_OK:
			continue;
		case SS_DROP:
			/*
			 * The packet is bad - don't spend resources to
			 * handle it in other callbacks.
			 */
			return r;
		case SS_POSTPONE:
			/*
			 * Remember that we have to postpone the packet and
			 * continue with it. If somebody decides that it must
			 * be dropped, then it will be dropped instead of
			 * postponing.
			 */
			ret = r;
			continue;
		}
	}

	return ret;
}
EXPORT_SYMBOL(ss_proto_run_handlers);

/**
 * Register new application protocol handler.
 */
void
ss_proto_push_handler(SsProto *proto, ss_proto_hndl_t handler)
{
	int i = 0;
	while (i < SS_MAX_PROTO_STACK_N && proto->handlers[i])
		++i;
	BUG_ON(i == SS_MAX_PROTO_STACK_N);

	proto->handlers[i] = handler;
}
EXPORT_SYMBOL(ss_proto_push_handler);
