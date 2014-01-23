/**
 * Synchronous Socket API.
 *
 * Generic protocols handling for session, presentation and application
 * (l5-l7) levels.
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
#ifndef __SS_PROTO_H__
#define __SS_PROTO_H__

#define SS_MAX_PROTO_STACK_N	4

void ss_proto_push_handler(SsProto *proto, ss_proto_hndl_t handler);

#endif /* __SS_PROTO_H__ */
