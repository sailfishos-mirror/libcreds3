/* vim: noexpandtab
 *
 * This file is part of AEGIS
 *
 * Copyright (C) 2009 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License 
 * version 2 as published by the Free Software Foundation. 
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * Author: Markku Savela
 */  

#ifndef _CREDS_FALLBACK_H_
#define _CREDS_FALLBACK_H_

#include <sys/types.h>
#include <linux/types.h>

#ifdef HAVE_LINUX_AEGIS_CREDS_H
#include <linux/aegis/creds.h>
#include <linux/aegis/credsctl.h>
#else

/* Use /proc/<pid> fallback hack, if kernel does
   not support creds api */


enum {
	CREDS_CAP = 0,	/* Capability Number -- cap_value_t */
	CREDS_UID,	/* User Identifier -- uid_t */
	CREDS_GID,	/* Group Identifier -- gid_t */
	CREDS_GRP,	/* Group Identifier -- gid_t */
	CREDS_SMACK,	/* Smack label -- _u32 */
	CREDS_MAX,
};

/*
 * The credentials for the policy are defined by a
 * sequence of TLV encoded values. The internal
 * structure of the value depends on the type.
 *
 * The following are defined now:
 *
 * T=CREDS_UID, L=1
 *	V[0] = uid
 * T=CREDS_GID, L=1
 *	V[0] = gid
 * T=CREDS_GRP, L>=0
 *	V[0..L-1] = set of supplementary gids
 * T=CREDS_CAP, L>0
 *	The value contains the capability bits
 *	the cabability bits are defined within this
 *	as "V[(capnum / 32)] |= (1 << (capnum % 32))"
 *	which should make this definition independent
 *	on any internal implementation of capability
 *	and number of supported capabilities.
 */
#define CREDS_TL(t, l) (((t) & 0xffff) | ((l) << 16))
#define CREDS_TLV_T(v) ((v) & 0xffff)
#define CREDS_TLV_L(v) ((unsigned)(v) >> 16)

long creds_kstr2creds(const char *str, long *value);
long creds_kget(pid_t pid, __u32 *list, size_t list_length);
long creds_kcreds2str(int type, long value, char *str, size_t str_len);

/* Exposed fallback function for userspace-only functionality */
int fallback_get(pid_t pid, __u32 *list, size_t list_length);

#endif
#endif
