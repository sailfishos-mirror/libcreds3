/* vim: noexpandtab
 *
 * This file is part of AEGIS
 *
 * Copyright (C) 2009-2010 Nokia Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * Authors:
 * Markku Savela (libcreds2)
 * Jarkko Sakkinen (migration to MeeGo and Smack)
 */

#define _ISOC99_SOURCE /* ..to get isblank from ctypes.h */
#define _GNU_SOURCE /* ..to get struct ucred from sys/socket.h */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <assert.h>
#include <smack.h>
#include <smackman.h>
#include <sys/capability.h>
#include "creds.h"
#include "creds_fallback.h"

#define SMACK_LABEL_SIZE 24

static const int initial_list_size =
	2 + /* uid */
	2 + /* gid */
	3 + /* caps */
	33; /* supplementary groups */

struct _creds_struct
	{
	long actual;		/* Actual list items */
	SmackRuleSet rules;
	SmackmanContext labels;
#ifdef CREDS_AUDIT_LOG
	creds_audit_t audit;	/* Audit information */
#endif
	size_t list_size;	/* Allocated list size */
	__u32 list[];		/* The list of items */
	};

/* Prefixes of supported credentials types used
 * by the string to value conversion.
 */
#define STRING(s) { s, sizeof(s)-1 }

static const struct
	{
	const char *const prefix;
	size_t len;
	}
creds_fixed_types[CREDS_MAX] =
	{
	[CREDS_UID] = STRING("UID::"),
	[CREDS_GID] = STRING("GID::"),
	[CREDS_GRP] = STRING("GRP::"),
	[CREDS_CAP] = STRING("CAP::"),
	[CREDS_SMACK] = STRING("SMACK::"),
	};

static const __u32 *find_value(int type, creds_t creds)
	{
	static const __u32 bad_tlv[] = {0};
	int i;

	if (! creds || creds->actual <= 0)
		return bad_tlv;

	for (i = 0; i < creds->actual; i += 1 + CREDS_TLV_L(creds->list[i]))
		if (CREDS_TLV_T(creds->list[i]) == type)
			return &creds->list[i];
	return bad_tlv;
	}

creds_t creds_init()
	{
	return NULL;
	}

void creds_clear(creds_t creds)
	{
#ifdef CREDS_AUDIT_LOG
	creds_audit_free(creds);
#endif
	if (creds)
		creds->actual = 0;
	}

void creds_free(creds_t creds)
	{
#ifdef CREDS_AUDIT_LOG
	creds_audit_free(creds);
#endif
	if (creds)
		{
		smack_rule_set_free(creds->rules);
		smackman_free(creds->labels);
		free(creds);
		}
	}

int creds_set(const creds_t creds)
{
	int i, j, k;
	creds_type_t t;
	int l;
	gid_t *grps = NULL;
	int grps_size = 0;
	cap_t caps = NULL;
	cap_value_t cvals[CAP_LAST_CAP + 1];
	int fd;
	ssize_t len;
	int pos;
	char smack[SMACK_LABEL_SIZE];

	if (! creds || creds->actual <= 0)
		return -1;

	i = 0;
	for (;;) {
		if (i >= creds->actual)
			break;

		t = CREDS_TLV_T(creds->list[i]);
		l = CREDS_TLV_L(creds->list[i]);

		switch (t) {
		case CREDS_UID:
			if (seteuid(creds->list[i + 1]) < 0)
				goto out;
			break;
		case CREDS_GID:
			if (setegid(creds->list[i + 1]) < 0)
				goto out;
			break;
		case CREDS_GRP:
			if (grps_size < l) {
				grps = realloc(grps, l * sizeof(gid_t));
				if (grps == NULL)
					goto out;
			}

			for (j = 0; j < l; j++)
				grps[j] = creds->list[i + j + 1];

			if (setgroups(l, grps) < 0)
				goto out;
			break;
		case CREDS_CAP:
			caps = cap_init();
			if (caps == NULL)
				goto out;

			k = 0;
			for (j = 0; j < (l * 32); ++j) {
				if (k > CAP_LAST_CAP)
					break;
				const int idx = 1 + i + j / 32;
				const __u32 bit = 1 << (j % 32);
				if (creds->list[idx] & bit) {
					cvals[k++] = j;
				}
			}

			if (cap_clear(caps) < 0)
				goto out;

			if (cap_set_flag(caps, CAP_PERMITTED,  k, cvals, CAP_SET) < 0)
				goto out;

			if (cap_set_flag(caps, CAP_EFFECTIVE,  k, cvals, CAP_SET) < 0)
				goto out;

			if (cap_set_proc(caps) < 0)
				goto out;

			cap_free(caps);
			break;
		case CREDS_SMACK:
			fd = open("/proc/self/attr/current", O_WRONLY);
			if (fd < 0)
				goto out;

			sprintf(smack, "SM-%08X", creds->list[i + 1]);

			pos = 0;
			for (;;) {
				len = write(fd, smack, SMACK_SHORT_LEN - pos, pos);
				if (len < 0)
					goto out;
				pos += len;
				if (pos >= SMACK_SHORT_LEN)
					break;
			}
			break;
		default:
			printf("Unknown\n");
			break;
		}

		i += l + 1;
	}

	return 0;
out:
	free(grps);
	cap_free(caps);
	return -1;
}

static void reverse(__u32 *base, int count)
{
	int i;
	for (i = 0; i < count; )
		{
		__u32 tmp = base[--count];
		base[count] = base[i];
		base[i++] = tmp;
		}
}

/*
 * Change the "payload size" of the item.
 *
 * @creds The pointer to creds handle.
 * @item Index the item to modify (T,L) or creds->actual
 * @type Type of the item
 * @count The new size (L) of the item.
 *
 * @return index (>= 0) of item, -1 on failure.
 *
 * This function may need to reallocate the creds content, thus
 * beware that content of the handle (*creds) can change.
 * NOTE SPECIALLY, that the change can also have occurred, even
 * if the actual operation fails!
 */
static int creds_adjust(creds_t *creds, int item, int type, size_t count)
{
	creds_t handle = *creds;
	int expand, i;

	assert(creds != NULL);

	if (item < handle->actual)
		{
		/* Existing entry must be modified */
		const size_t item_len = CREDS_TLV_L(handle->list[item]) + 1;
		const size_t rotate = item + item_len;
		expand = count - CREDS_TLV_L(handle->list[item]);
		if (expand == 0)
			return item; /* Nothing to do */
		if (rotate < handle->actual)
			{
			/* The entry is not the last item in
			 * creds, make it last ...
			 */
			reverse(handle->list + rotate, handle->actual - rotate);
			reverse(handle->list + item, item_len);
			reverse(handle->list + item, handle->actual - item);
			item = handle->actual - item_len;
			}
		}
	else
		{
		/* No previous entry, create a new TL header */
		if (count == 0)
			return -1; /* ..don't create empty TLV */
		item = handle->actual;
		if (handle->list_size == handle->actual)
			{
			/* No room at all, reallocate the handle */
			const size_t new_size = handle->actual + count + 1;
			handle = (creds_t)realloc(handle, sizeof(*handle) + new_size * sizeof(handle->list[0]));
			if (!handle)
				return -1;/* Memory allocation failure */
			/* Success */
			handle->list_size = new_size;
			*creds = handle;
			}
		handle->list[item] = CREDS_TL(type, 0);
		handle->actual += 1;
		expand = count;
		}
	/* Add expand items to the current item */
	if (handle->actual + expand > handle->list_size)
		{
		/* No room for added values */
		const size_t new_size = handle->actual + expand;
		handle = (creds_t)realloc(handle, sizeof(*handle) + new_size * sizeof(handle->list[0]));
		if (!handle)
			return -1;/* Memory allocation failure */
		/* Success */
		handle->list_size = new_size;
		*creds = handle;
		}
	handle->list[item] = CREDS_TL(CREDS_TLV_T(handle->list[item]), CREDS_TLV_L(handle->list[item]) + expand);
	if (CREDS_TLV_L(handle->list[item]) == 0)
		{
		/* Remove the item fully */
		handle->actual = item;
		return -1;
		}
	handle->actual += expand;

	/* Zero out new values at end */
	for (i = item + CREDS_TLV_L(handle->list[item]); --expand >= 0; --i)
		handle->list[i] = 0;
	return item;
}

int creds_add(creds_t *creds, creds_type_t type, creds_value_t value)
{
	int i, j;
	creds_t handle;
	if (!creds)
		return -1;
	handle = *creds;
	if (!handle)
		{
		/* Create an empty creds structure */
		handle = (creds_t)malloc(sizeof(*handle) + initial_list_size * sizeof(handle->list[0]));
		if (!handle)
			return -1; /* Failed */
#ifdef CREDS_AUDIT_LOG
		creds_audit_init(handle, -1);
#endif
		handle->list_size = initial_list_size;
		handle->actual = 0;
		*creds = handle;
		}

	for (i = 0; i < handle->actual; i += 1 + CREDS_TLV_L(handle->list[i]))
		if (CREDS_TLV_T(handle->list[i]) == type)
			break;
	assert(i <= handle->actual);
	/* i points to found item or i == handle->actual, if not found */

	switch (type)
		{
		case CREDS_CAP:
			i = creds_adjust(creds, i, CREDS_CAP, 2);
			if (i < 0)
				return -1;
			handle = *creds;
			assert(type == CREDS_TLV_T(handle->list[i]));

			if (value >= 0 && value < CREDS_TLV_L(handle->list[i]) * 32)
				{
				const int idx = i + 1 + (value / 32);
				const __u32 bit = 1 << (value % 32);
				handle->list[idx] |= bit;
				return 0;
				}
			return -1; /* Fail, invalid capability value */
		case CREDS_UID:
		case CREDS_GID:
			i = creds_adjust(creds, i, type, 1);
			if (i < 0)
				return -1;
			assert(type == CREDS_TLV_T(handle->list[i]));
			handle = *creds;
			handle->list[i+1] = value;
			return 0;
		case CREDS_GRP:
			if (i < handle->actual)
				{
				/* GRP exists, check for duplicate */
				for (j = 0; j < CREDS_TLV_L(handle->list[i]); ++j)
					if (handle->list[i+1+j] == value)
						return 0; /* Already there, nothing to do */
				/* Not there, need to expand GRP */
				j = CREDS_TLV_L(handle->list[i]);
				}
			else
				j = 0;
			i = creds_adjust(creds, i, CREDS_GRP, j + 1);
			if (i < 0)
				return -1;
			assert(type == CREDS_TLV_T(handle->list[i]));

			handle = *creds;
			handle->list[i+1+j] = value;
			return 0;
		default:
			break;
		}
	return -1;
}

void creds_sub(creds_t creds, creds_type_t type, creds_value_t value)
{
	int i, j;

	if (!creds)
		return;

	for (i = 0; ; i += 1 + CREDS_TLV_L(creds->list[i]))
		{
		if (i >=  creds->actual)
			return; /* Not found */
		if (CREDS_TLV_T(creds->list[i]) == type)
			break;
		}

	switch (type)
		{
		case CREDS_CAP:
			if (value >= 0 && value < CREDS_TLV_L(creds->list[i]) * 32)
				{
				const int idx = i + 1 + (value / 32);
				const __u32 mask = ~(1 << (value % 32));
				creds->list[idx] &= mask;
				}
			break;
		case CREDS_UID:
		case CREDS_GID:
			i = creds_adjust(&creds, i, type, 0);
			break;
		case CREDS_GRP:
			for (j = 0;; ++j)
				if (j == CREDS_TLV_L(creds->list[i]))
					return; /* Not found */
				else if (creds->list[i+1+j] == value)
					break;
			/* Overwrite the value to be removed by
			   by the last value, and adjust size ... */

			creds->list[i+1+j] =
				creds->list[i + CREDS_TLV_L(creds->list[i])];
			i = creds_adjust(&creds, i, CREDS_GRP, CREDS_TLV_L(creds->list[i]) - 1);
			break;
		default:
			break;
		}

}

creds_t creds_getpeer(int fd)
	{
	struct ucred cr;
	size_t cr_len = sizeof(cr);
	if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) == 0 &&
		cr_len == sizeof(cr))
		return creds_gettask(cr.pid);
	return NULL;
	}

creds_t creds_gettask(pid_t pid)
{
	creds_t handle = NULL;
	long actual = initial_list_size;
	int maxtries = 4;

	handle = (creds_t)calloc(1, sizeof(struct _creds_struct) + actual * sizeof(__u32));
	handle->list_size = initial_list_size;

	handle->rules = smack_rule_set_new(SMACKMAN_LOAD_PATH);
	if (handle->rules == NULL)
		goto out;
	handle->labels = smackman_new(NULL, SMACKMAN_LABELS_PATH);
	if (handle->labels == NULL)
		goto out;

	do {
		creds_t new_handle = (creds_t)realloc(handle, sizeof(struct _creds_struct) + actual * sizeof(__u32));
		if (new_handle == NULL)
			goto out;
#ifdef CREDS_AUDIT_LOG
		if (handle == NULL)
			creds_audit_init(new_handle, pid);
#endif
		handle = new_handle;

		handle->list_size = actual;
		handle->actual = actual =
			fallback_get(pid, handle->labels, handle->list,
				     handle->list_size);
		/* warnx("max items=%d, returned %ld", handle->list_size, actual); */
		if (actual < 0) {
			/* Some error detected */
			errno = -actual;
			creds_free(handle);
			handle = NULL;
			break;
		}
	} while (handle->list_size < actual && --maxtries > 0);

	return handle;
out:
	creds_free(handle);
	return NULL;
}

static int numeric_p(const char *str, long *value)
	{
	/* Note: this internal help function assumes
	   that both str and value are not NULL, and
	   that str is not empty! */
	
	char *endptr;
	int saved = errno;
	int ret = 1;

	errno = 0;
	*value = strtol(str, &endptr, 10);
	if (errno || *endptr)
		ret = 0; /* numeric conversion failed */
	errno = saved;
	return ret;
	}

static long creds_str2uid(const char *user)
	{
	int retry;
	char *buf = NULL;
	size_t buflen = 1024;
	uid_t uid = CREDS_BAD;
	long nbr;
	
	if (!user || !*user)
		return uid;

	if (numeric_p(user, &nbr))
		return nbr;

	for (retry = 0; retry < 5; ++retry)
		{
		int res;
		struct passwd p;
		struct passwd *pptr = NULL;
		char *newbuf = (char *)realloc(buf, buflen);

		if (!newbuf)
			break;
		buf = newbuf;
		res = getpwnam_r(user, &p, buf, buflen, &pptr);
		if (res == 0 && pptr == &p)
			{
			uid = p.pw_uid;
			break; /* Converted user to uid successfully */
			}
		if (res != ERANGE)
			break;
		buflen *= 2;
		}
	if (buf)
		free(buf);
	return uid;
}

static long creds_str2gid(const char *group)
{
	int retry;
	char *buf = NULL;
	size_t buflen = 1024;
	gid_t gid = CREDS_BAD;
	long nbr;

	if (!group || !*group)
		return gid;

	if (numeric_p(group, &nbr))
		return nbr;

	for (retry = 0; retry < 5; ++retry) {
		int res;
		struct group g;
		struct group *gptr = NULL;
		char *newbuf = (char *)realloc(buf, buflen);

		if (!newbuf)
			break;
		buf = newbuf;
		res = getgrnam_r(group, &g, buf, buflen, &gptr);
		if (res == 0 && gptr == &g) {
			gid = g.gr_gid;
			break; /* Converted group to gid successfully */
		}
		if (res != ERANGE)
			break;
		buflen *= 2;
	}
	if (buf)
		free(buf);
	return gid;
}

static long creds_str2smack(const char *credential, creds_value_t *value)
{
	SmackmanContext ctx;
	const char *short_name;
	int len;

	ctx = smackman_new(NULL, SMACKMAN_LABELS_PATH);
	if (ctx == NULL)
		return CREDS_BAD;

	/* Return error *always* when caller tries to access
	 * credential that does not exist in our labels database.
	 */
	short_name = smackman_to_short_name(ctx, credential);
	if (short_name == NULL) {
		smackman_free(ctx);
		return CREDS_BAD;
	}

	*value = strtoll(short_name + SMACK_SHORT_PREFIX_LEN,
			 (char **)NULL, 16);

	smackman_free(ctx);
	return CREDS_SMACK;
}

static long creds_typestr2creds(creds_type_t type, const char *credential)
{
	long value;

	if (numeric_p(credential, &value))
		return value;

	switch (type) {
	case CREDS_UID:
		return creds_str2uid(credential);
	case CREDS_GID:
	case CREDS_GRP:
		return creds_str2gid(credential);
	default:
		break;
	}
	return CREDS_BAD;
}

long creds_str2creds(const char *credential, creds_value_t *value)
{
	int len;
	long i;
	char *endptr;
	creds_value_t dummy;

	/* Allow calls with NULL as return value! Handy, if
	   translating namespace only, e.g. bare prefix, like
	   "UID::"
	 */
	if (!value)
		value = &dummy;

	*value = CREDS_BAD;
	if (!credential)
		return CREDS_BAD;

	len = strlen(credential);

	/* See, if kernel translates it */
	i = fallback_str2creds(credential, value);
	if (i >= 0)
		return i; /* ..yes, kernel did it! */

	/* Try some known fixed types */
	*value = CREDS_BAD;
	for (i = 0; i < sizeof(creds_fixed_types) / sizeof(creds_fixed_types[0]); ++i) {
		const size_t cmplen = creds_fixed_types[i].len;
		if (cmplen > 0 && cmplen <= len &&
		    memcmp(creds_fixed_types[i].prefix, credential, cmplen) == 0) {
			/* prefix matched */
			if (len == cmplen)
				return i; /* .. bare prefix special case */
			credential += cmplen;
			if (i == CREDS_SMACK)
				return creds_str2smack(credential, value);
			*value = creds_typestr2creds(i, credential);
			return (*value == CREDS_BAD) ? CREDS_BAD : i;
		}
	}

	/* Final fallback, see if the namespace numerical */
	i = strtol(credential, &endptr, 10);
	if (endptr[0] == ':' && endptr[1] == ':') {
		/* Numerical typevalue given */
		if (endptr[2] == 0)
			return i; /* .. bare (numeric)prefix special case */
		if (i == CREDS_SMACK)
			return creds_str2smack(credential, value);
		*value = creds_typestr2creds(i, endptr+2);
		return (*value == CREDS_BAD) ? CREDS_BAD : i;
	}
	return CREDS_BAD;
}

creds_type_t creds_list(const creds_t creds, int index, creds_value_t *value)
	{
	int i, j;

	if (! creds || creds->actual <= 0)
		return CREDS_BAD;
	
	for (i = 0; i < creds->actual; i += 1 + CREDS_TLV_L(creds->list[i]))
		switch (CREDS_TLV_T(creds->list[i]))
			{
			case CREDS_UID: /* The value is UID */
				if (index == 0)
					{
					*value = creds->list[i+1];
					return CREDS_UID;
					}
				--index;
				break;
			case CREDS_GID: /* The value is GID */
				if (index == 0)
					{
					*value = creds->list[i+1];
					return CREDS_GID;
					}
				--index;
				break;
			case CREDS_GRP: /* The value is set of GID */
				if (index < CREDS_TLV_L(creds->list[i]))
					{
					*value = creds->list[i+1+index];
					return CREDS_GRP;
					}
				index -= CREDS_TLV_L(creds->list[i]);
				break;

			case CREDS_CAP: /* The value is capability number */
				for (j = 0; j < 32 * CREDS_TLV_L(creds->list[i]); ++j)
					{
					const int idx = 1 + i + j / 32;
					const __u32 bit = 1 << (j % 32);
					if (creds->list[idx] & bit)
						{
						if (index == 0)
							{
							*value = j;
							return CREDS_CAP;
							}
						--index;
						}
					}
				break;
			case CREDS_SMACK:
				if (index == 0)
					{
					*value = creds->list[i+1];
					return CREDS_SMACK;
					}
				--index;
				break;
			default:
				break;
			}

	return CREDS_BAD;
	}

/*
** match() Iterative matching function, rather than recursive. Based
** on version for irc daemon (lincence GPL) written by Douglas A Lewis
** (dalewis@acsu.buffalo.edu)
*/
static int match(const char *m, const char *n)
	{
	const char *ma = NULL, *na = NULL;
	
	if (!m || !n)
		return 1;

	while (1)
		{
		while (*m == '*')
			{
			ma = ++m;
			na = n;
			}
		
		while (!*m)
			{
	  		if (!*n)
				return 0;
			if (!ma)
				return 1;
			if (m == ma)
				return 0; /* m ends with '*' -- matches all remaining n */
			m = ma;
			n = ++na;
			}

		/* *m is not NUL and not '*'! */

		if (!*n)
			return 1;

		/* Both *m and *n not NUL */

		if (*m == *n || *m == '?')
			{
			m++;
			n++;
			}
		else if (ma)
			{
			m = ma;
			n = ++na;
			}
		else
			break;
		}
	return 1;
	}

int creds_find(const creds_t creds, const char *pattern, char *buf, size_t size)
{
	int i;
	int res = CREDS_BAD;
	size_t len = 0;

	/* ...verify for sensible arguments */
	if (!creds || creds->actual <= 0 || pattern == NULL || buf == NULL)
		return CREDS_BAD;

	/* Note: This function could be implemented simply by calling
	 * creds_list and creds_cred2str iteratively. The more complicated
	 * implementation attempts to be faster by trying to limit the
	 * number of credentials that need to be translated into string...
	 */

	/* Count the non-wild characters from pattern start */
	while (pattern[len] && pattern[len] != '*' && pattern[len] != '?')
		++len;

	for (i = 0; i < creds->actual; i += 1 + CREDS_TLV_L(creds->list[i]))
		{
		const creds_type_t type = CREDS_TLV_T(creds->list[i]);
		int j;

		/* If we have non-wild start in pattern, and the type is
		 * one of the fixed types, then we can skip this,
		 * if the pattern start does not match the beginning
		 * type.
		 * Note: CREDS_GRP must be excluded from this, because
		 * it includes strings, which do not start with GRP::!
		 */
		if (type != CREDS_GRP && type < CREDS_MAX && type >= 0)
			{
			const size_t cmplen = (len < creds_fixed_types[type].len) ? len : creds_fixed_types[type].len;
			if (cmplen > 0 && memcmp(pattern, creds_fixed_types[type].prefix, cmplen) != 0)
				continue; /* Pattern will never match these, look for next */
			}

		for (j = 0; j < CREDS_TLV_L(creds->list[i]); ++j)
			{
			const creds_value_t value = creds->list[i+1+j];
			int k;

			if (type != CREDS_CAP)
				{
				/* Translate 'type,value' into string and check whether it matches with
				 * the pattern. If does, return this result.
				 */
				res = creds_creds2str(type, value, buf, size);
				if (res < 0 || res >= size || match(pattern, buf) == 0)
					return res;
				}
			else for (k = 0; k < 32; ++k)
				{
				const int capnbr = j * 32 + k;
				const __u32 bit = 1 << k;
				if (value & bit)
					{
					/* Translate 'type,value' into string and check whether it matches with
					 * the pattern. If does, return this result.
					 */
					res = creds_creds2str(type, capnbr, buf, size);
					if (res < 0 || res >= size || match(pattern, buf) == 0)
						return res;
					}
				}
			res = CREDS_BAD;
			}
		}
	return res;
}

int creds_have_access(const creds_t creds, creds_type_t type, creds_value_t value, const char *access_type)
{
	char object[SMACK_LABEL_SIZE];
	char subject[SMACK_LABEL_SIZE];
	const __u32 *item;
	int res;

	res = creds_have_p(creds, type, value);
	if (res || type != CREDS_SMACK)
		return res;

	item = find_value(CREDS_SMACK, creds);
	if (CREDS_TLV_L(*item) != 1)
		return 0;

	sprintf(subject, SMACK_SHORT_PREFIX "%08X", item[1]);
	sprintf(object, SMACK_SHORT_PREFIX "%08X", value);

	/* Return no access *always* when caller tries to access
	 * credential that does not exist in our labels database.
	 */
	if (smackman_to_long_name(creds->labels, object) == NULL)
		return 0;

	return smack_rule_set_have_access(creds->rules,
					  subject,
					  object,
					  access_type);
}

int creds_have_p(const creds_t creds, creds_type_t type, creds_value_t value)
{
	int i;
	const __u32 *item;

	if (! creds)
		return 0;

	item = find_value(type, creds);
	switch (type)
		{
		case CREDS_CAP:
			if (value >= 0 && value < CREDS_TLV_L(*item) * 32)
				{
				const int idx = 1 + (value / 32);
				const __u32 bit = 1 << (value % 32);
				if (item[idx] & bit)
					return 1;
				}
			break;
		case CREDS_GRP:
			for (i = 0; i < CREDS_TLV_L(*item); ++i)
				if (item[i+1] == value)
					return 1;
			item = find_value(CREDS_GID, creds);
			/* FALL THROUGH, CREDS_GRP includes CREDS_GID test */
		case CREDS_UID:
		case CREDS_GID:
			if (CREDS_TLV_L(*item) == 1 && item[1] == value)
				return 1;
			break;
		case CREDS_SMACK:
			if (CREDS_TLV_L(*item) == 1 && item[1] == value)
				return 1;
			break;
		default:
			break;
		}
#ifdef CREDS_AUDIT_LOG
	/*
	 * Return "OK" for all tests, but log the failed ones.
	 */
	creds_audit_log(creds, type, value);
	return 1;
#else
	return 0;
#endif
	}



static int creds_gid2str(creds_type_t type, creds_value_t value, char *buf, size_t size)
{
	int retry;
	char *group = NULL;
	char *tmp = NULL;
	size_t tmplen = 1024;
	int len;

	for (retry = 0; retry < 5; ++retry) {
		int res;
		struct group g;
		struct group *gptr = NULL;
		char *newtmp = (char *)realloc(tmp, tmplen);

		if (!newtmp)
			break;
		tmp = newtmp;
		res = getgrgid_r(value, &g, tmp, tmplen, &gptr);
		if (res == 0 && gptr == &g) {
			group = g.gr_name;
			break; /* Converted gid to group successfully */
		}
		if (res != ERANGE)
			break;
		tmplen *= 2;
	}
	if (group)
		len = snprintf(buf, size, "%s%s", creds_fixed_types[type].prefix, group);
	else
		len = snprintf(buf, size, "%s%d", creds_fixed_types[type].prefix, (int)value);
	if (tmp)
		free(tmp);
	return len;
}

static int creds_uid2str(creds_type_t type, creds_value_t value, char *buf, size_t size)
{
	int retry;
	char *user = NULL;
	char *tmp = NULL;
	size_t tmplen = 1024;
	int len;

	for (retry = 0; retry < 5; ++retry) {
		int res;
		struct passwd p;
		struct passwd *pptr = NULL;
		char *newtmp = (char *)realloc(tmp, tmplen);

		if (!newtmp)
			break;
		tmp = newtmp;
		res = getpwuid_r(value, &p, tmp, tmplen, &pptr);
		if (res == 0 && pptr == &p) {
			user = p.pw_name;
			break; /* Converted uid to user successfully */
		}
		if (res != ERANGE)
			break;
		tmplen *= 2;
	}
	if (user)
		len = snprintf(buf, size, "%s%s", creds_fixed_types[type].prefix, user);
	else
		len = snprintf(buf, size, "%s%d", creds_fixed_types[type].prefix, (int)value);
	if (tmp)
		free(tmp);
	return len;
}

static int creds_smack2str(creds_type_t type, creds_value_t value, char *buf, size_t size)
{
	SmackmanContext ctx;
	char short_name[SMACK_LABEL_SIZE];
	const char *long_name;
	int len;

	ctx = smackman_new(NULL, SMACKMAN_LABELS_PATH);
	if (ctx == NULL)
		return -1;

	sprintf(short_name, SMACK_SHORT_PREFIX "%08X", value);

	/* Return error *always* when caller tries to access
	 * credential that does not exist in our labels database.
	 */
	long_name = smackman_to_long_name(ctx, short_name);
	if (long_name == NULL) {
		smackman_free(ctx);
		return -1;
	}

	len = snprintf(buf, size, "%s%s", creds_fixed_types[type].prefix,
		       long_name);

	smackman_free(ctx);

	return len;
}

int creds_creds2str(creds_type_t type, creds_value_t value, char *buf, size_t size)
{
	long ret = fallback_creds2str(type, value, buf, size);
	if (ret >= 0)
		return ret;

	/* Special case: type correct, but value unspecied, just
	   return the "XXX::" prefix */
	if (value == CREDS_BAD &&
	    type >= 0 && type < CREDS_MAX &&
	    creds_fixed_types[type].prefix)
		return snprintf(buf, size, "%s", creds_fixed_types[type].prefix);

	switch (type) {
	case CREDS_UID:
		return creds_uid2str(type, value, buf, size);
	case CREDS_GRP:
	case CREDS_GID:
		return creds_gid2str(type, value, buf, size);
	case CREDS_SMACK:
		return creds_smack2str(type, value, buf, size);
	default:
		break;
	}
	return snprintf(buf, size, "%d::%ld", (int)type, (long)value);
}

const uint32_t *creds_export(creds_t creds, size_t *length)
{
	if (!length)
		return NULL;
	if (!creds) {
		*length = 0;
		return NULL;
	}
	*length = creds->actual;
	return creds->list;
}

creds_t creds_import(const uint32_t *list, size_t length)
{
	creds_t handle;

	handle = (creds_t)malloc(sizeof(*handle) + length * sizeof(handle->list[0]));
	if (!handle)
		return NULL;

	handle->rules = smack_rule_set_new(SMACKMAN_LOAD_PATH);
	if (handle->rules == NULL)
		goto out;

	handle->labels = smackman_new(NULL, SMACKMAN_LABELS_PATH);
	if (handle->labels == NULL)
		goto out;

	handle->actual = handle->list_size = length;
	memcpy(handle->list, list, length * sizeof(handle->list[0]));
#ifdef CREDS_AUDIT_LOG
	creds_audit_init(handle, -1);
#endif
	return handle;
out:
	creds_free(handle);
	return NULL;
}

