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
 * Author: Markku Savela
 */

/*
 * This implementation of libcreds assumes existence of the credpol kernel
 * module.
 */
#define _ISOC99_SOURCE /* ..to get isblank from ctypes.h */
#define _GNU_SOURCE /* ..to get struct ucred from sys/socket.h */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <assert.h>
#include <sys/smack.h>

#include "sys/creds.h"

/*
 * 'creds' is pure information retrieval API
 */
#include "creds_fallback.h"

#define SMACK_LABEL_MAX_LEN 24


static const int initial_list_size =
	2 + /* uid */
	2 + /* gid */
	3 + /* caps */
	33; /* supplementary groups */


struct _creds_struct
	{
	long actual;		/* Actual list items */
	char smack_str[SMACK_LABEL_MAX_LEN];
	creds_value_t smack_value;
	SmackRuleSet rules;
#ifdef CREDS_AUDIT_LOG
	creds_audit_t audit;	/* Audit information */
#endif
	size_t list_size;	/* Allocated list size */
	__u32 list[40];		/* The list of items, initial_list_size */
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
		smack_rule_set_delete(creds->rules);
		free(creds);
		}
	}

/**
 * Userspace-only "replacement" for creds_kget()
 *
 * The SMACK label for the given process is read from
 * /proc/PID/attr/current, and since libsmack happily provides that
 * routine, we'll pull the label from there.
 *
 * The credentials are exported via /proc/PID/status. The call to
 * pid_details() returns all of these combined, but it means that each
 * call actually performs two distinct open()/read()/close/() cycles.
 */
static long creds_proc_get(const pid_t pid, char *smack,
	__u32 *list, const int list_size)
{
	long nr_items = 0;
	__u32 tl = CREDS_BAD;
	int i;

	nr_items = fallback_get(pid, list, list_size);
	i = smack_xattr_get_from_proc(pid, smack, SMACK_LABEL_MAX_LEN, NULL);
	/* FIXME: handle error case if return value is -1 */

	return nr_items;
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
	SmackRuleSet rules = NULL;
	long actual = initial_list_size;
	int maxtries = 4;

	rules = smack_rule_set_new_from_file(SMACK_ACCESSES_PATH, NULL, NULL);
	if (rules == NULL)
		return NULL;

	do
		{
		creds_t new_handle = (creds_t)realloc(handle, sizeof(*handle) + actual * sizeof(handle->list[0]));
		if (! new_handle)
			{
			/* Memory allocation failure */
			creds_free(handle);
			handle = NULL;
			break;
			}
#ifdef CREDS_AUDIT_LOG
		if (handle == NULL)
			creds_audit_init(new_handle, pid);
#endif
		handle = new_handle;
		handle->list_size = actual;
		handle->actual = actual = creds_proc_get(pid,
				handle->smack_str, handle->list, handle->list_size);
		handle->smack_value = strtol(handle->smack_str, (char **)NULL, 16);
		/* warnx("max items=%d, returned %ld", handle->list_size, actual); */
		if (actual < 0)
			{
			/* Some error detected */
			errno = -actual;
			creds_free(handle);
			handle = NULL;
			break;
			}
		}
	while (handle->list_size < actual && --maxtries > 0);

	if (handle != NULL)
		handle->rules = rules;
	else
		smack_rule_set_delete(rules);

	return handle;
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

static long creds_str2smack(const char *smack_long)
{
	char short_name[9];
	long val;

	smack_label_set_get_short_name(smack_long, short_name);
	val = strtol(short_name, (char **)NULL, 16);
	return val;
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
	case CREDS_SMACK:
		return creds_str2smack(credential);
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
	i = creds_kstr2creds(credential, value);
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
			default:
				break;
			}

	if (i == creds->actual)
		{
		*value = creds->smack_value;
		return CREDS_SMACK;
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
	int res = CREDS_BAD;
	creds_value_t value;
	creds_type_t type = CREDS_BAD;
	int index;

	/* ...verify for sensible arguments */
	if (!creds || creds->actual <= 0 || pattern == NULL || buf == NULL)
		return CREDS_BAD;

	for (;;) {
		type = creds_list(creds, index, &value);
		if (type == CREDS_BAD)
			break;

		res = creds_creds2str(type, value, buf, size);
		if (res < 0 || res >= size || match(pattern, buf) == 0)
			return res;
	}

	return CREDS_BAD;
}

int creds_have_access(const creds_t creds, creds_type_t type, creds_value_t value, const char *access_type)
{
	char str[9];
	int res;

	res = creds_have_p(creds, type, value);
	if (res || type != CREDS_SMACK)
		return res;

	sprintf(str, "%X", value);

	return smack_rule_set_have_access(creds->rules,
					  creds->smack_str,
					  str, access_type,
					  NULL);
}

int creds_have_p(const creds_t creds, creds_type_t type, creds_value_t value)
{
	int i;
	const __u32 *item;

	if (! creds)
		return 0;

	if (type == CREDS_SMACK)
		return value == creds->smack_value;

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
	SmackLabelSet labels;
	char short_name[9];
	const char *long_name;
	int len;

	labels = smack_label_set_new_from_file(SMACK_LABELS_PATH);
	if (labels == NULL)
		return -1;

	sprintf(short_name, "%X", value);
	long_name = smack_label_set_to_long_name(labels, short_name);
	if (long_name == NULL)
		return -1;

	len = snprintf(buf, size, "%s%s", creds_fixed_types[type].prefix,
		       long_name);

	smack_label_set_delete(labels);

	return len;
}

int creds_creds2str(creds_type_t type, creds_value_t value, char *buf, size_t size)
{
	long ret = creds_kcreds2str(type, value, buf, size);
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
	SmackRuleSet rules;
	creds_t handle;

	rules = smack_rule_set_new_from_file(SMACK_ACCESSES_PATH, NULL, NULL);
	if (rules == NULL)
		return NULL;

	handle = (creds_t)malloc(sizeof(*handle) + length * sizeof(handle->list[0]));
	if (!handle)
		{
		smack_rule_set_delete(rules);
		return NULL;
		}

	handle->rules = rules;

	handle->actual = handle->list_size = length;
	memcpy(handle->list, list, length * sizeof(handle->list[0]));
#ifdef CREDS_AUDIT_LOG
	creds_audit_init(handle, -1);
#endif
	return handle;
}







