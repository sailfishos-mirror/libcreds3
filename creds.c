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
	char smacklabel[SMACK_LABEL_MAX_LEN];
#ifdef CREDS_AUDIT_LOG
	creds_audit_t audit;	/* Audit information */
#endif
	size_t list_size;	/* Allocated list size */
	__u32 list[40];		/* The list of items, initial_list_size */
	};


/* Helper container for various process identifiers, as read from
 * /proc/PID/stat, /proc/PID/status and possibly other pseudofs paths.
 */
struct pid_tidbits {
	/**
	 * /proc/PID/stat
	 */
	pid_t pid;		/* 1st field */
	pid_t ppid;		/* 4th field */
	pid_t pgrp;		/* 5th field */
	pid_t sid;		/* 6th field */
	unsigned int tty_nr;	/* 7th field */

	/**
	 * /proc/PID/status
	 */
	uid_t uid;		/* Effective: prefixed by "Uid:" */
	gid_t gid;		/* Effective: prefixed by "Gid:" */
	__u32 kcaps[2];		/* Effective; prefixed by "CapEff:" */
	__u32 grps[32];		/* prefixed by "Groups:" */
	unsigned int ngroups;
};

/**
 * Helper routine to read given /proc/PID/stat, /proc/PID/status .
 * Caller must free the returned structure after use.
 */
static struct pid_tidbits *pid_details(const pid_t pid)
{
	struct pid_tidbits *details = NULL;
	int fd1, fd2;
	ssize_t r;
	int ret, i;
	char fp1[256];
	char fp2[256];
	char *buf, *buf2, *buf3, *buf4;;
	char *field, *line;
	char ascint[9];

	memset(ascint, 0, 9);

	ret = snprintf(fp1, 255, "/proc/%u/stat", pid);
	if (ret <= 0)
		return NULL;
	ret = snprintf(fp2, 255, "/proc/%u/status", pid);
	if (ret <= 0)
		return NULL;

	/* Because this is already hideously racy, we're stacking the
	 * open()/close() calls so they at least occur as close to each
	 * other as possible.
	 */
	fd1 = open(fp1, O_RDONLY);
	if (!fd1) {
		perror("open");
		return NULL;
	}

	fd2 = open(fp2, O_RDONLY);
	if (!fd2) {
		perror("open");
		close(fd1);
		return NULL;
	}


	details = calloc(sizeof(struct pid_tidbits), 1);
	if (!details) {
		perror("calloc");
		close(fd1);
		close(fd2);
		return NULL;
	}

	buf = calloc(4096, sizeof(char));
	buf2 = calloc(256, sizeof(char));

	buf3 = calloc(4096, sizeof(char));
	buf4 = buf3; /* srtsep() modifies its argument */

	r = read(fd1, buf, 4096);
	close(fd1);
	if (r < 0) {
		perror("read");
		close(fd2);
		free(buf);
		free(buf3);
	}

	r = read(fd2, buf3, 4096);
	close(fd2);
	if (r < 0) {
		perror("read");
		free(buf);
		free(buf3);
	}

	/* Extract tokens from line via sscanf()
	 *
	 * XXX: This is insecure and fragile. If process name includes
	 * embedded space(s), things will break. The worst thing here is
	 * that the second fmtstring argument can not be "(%s)"; if that is
	 * used, the picked string will be "NAME)", with the closing
	 * parenthesis postfixed. After that, the state indicator will be
	 * empty, and the rest of the string naturally is parsed wrong.
	 */
	char *dummy = calloc(32, sizeof(char));
	ret = sscanf(buf, "%u %s %s %u %u %u %u",
			&details->pid,
			buf2, dummy,	/* reused pointer, unused values */
			&details->ppid,
			&details->pgrp,
			&details->sid,
			&details->tty_nr );
	free(dummy);
	free(buf);
	free(buf2);


	/* Okay, then to /proc/PID/status contents.
	 * The file contains lots of newlines, so we'll have to seek into
	 * the lines and fields we need.
	 */

	/* Find uid */
	while (1) {
		line = strsep(&buf3, "\n");
		if (strncmp(line, "Uid:", 4) == 0)
			break;
	}
	field = strsep(&line, "\t"); /* finds "Uid:" */
	field = strsep(&line, "\t");
	field = strsep(&line, "\t"); /* euid: second item */
	details->uid = atoi(field);

	/* Shortcut: Gid is immediately followed by Uid */
	line = strsep(&buf3, "\n");
	field = strsep(&line, "\t"); /* finds "Gid:" */
	field = strsep(&line, "\t");
	field = strsep(&line, "\t"); /* egid: second item */
	details->gid = atoi(field);

	/* Find the groups */
	while (1) {
		line = strsep(&buf3, "\n");
		if (strncmp(line, "Groups:", 7) == 0)
			break;
	}
	field = strsep(&line, "\t"); /* Go past "Group:\t" */
	/* reuse buf, buf2 */
	buf = strdup(line);
	buf2 = buf;
	i = 0;
	while (strlen(field) >= 1) {
		field = strsep(&buf, " ");
		if (field[0] == '\0')
			break;
		details->grps[i++] = atoi(field);
		if (i == 32) /* Catch nasty corner case */
			break;
	}
	details->ngroups = i;
	free(buf2);


	/* According to linux/fs/proc/array.c the kernel capabilities are
	 * exported via /proc/PID/status but the format is not really
	 * documented. Capabilities are a 64-bit bitmask, packed into
	 * two __u32's and printed as a single string, "%08x%08x"
	 */

	/* Find the bitmask value of CapEff */
	while (1) {
		line = strsep(&buf3, "\n");
		if (strncmp(line, "CapEff:", 7) == 0)
			break;
	}
	field = strsep(&line, "\t"); /* finds "EffGrp:" */
	field = strsep(&line, "\n");
	memcpy(ascint, field, 8);
	/* Mask is printed in hex */
	details->kcaps[0] = (__u32) strtol(ascint, NULL, 16);
	details->kcaps[1] = (__u32) strtol(field+8, NULL, 16);

	free(buf4);

	return details;
}

static int tidbit_cmp(struct pid_tidbits *p1, struct pid_tidbits *p2)
{
	int i;
	if (p1->ngroups != p2->ngroups)
		return 0;
	for (i = 0; i < p1->ngroups; i++)
		if (p1->grps[i] != p2->grps[i])
			return 0;

	return (p1->pid == p2->pid &&
		p1->ppid == p2->ppid &&
		p1->pgrp == p2->pgrp &&
		p1->sid == p2->sid &&
		p1->tty_nr == p2->tty_nr &&
		p1->kcaps[0] == p2->kcaps[0] &&
		p1->kcaps[1] == p2->kcaps[1]
		);
}



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
		free(creds);
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
	struct pid_tidbits *p1;
	struct pid_tidbits *p2;
	long nr_items = 0;
	__u32 tl = CREDS_BAD;
	int i;

	/* This is a desperate trick. Pid may change between calls, so we
	 * read the values for pid once, then the smack label, and then the
	 * values for pid again. Only if the two sets of values are exactly
	 * the same, can we assume that the process stayed the same all the
	 * time.
	 *
	 * XXX: This is _NOT_ secure, since credentials are not read
	 * atomically. It is just the best estimate until more robust kernel
	 * interface is provided.
	 */
	p1 = pid_details(pid);
	i = smack_xattr_get_from_proc(pid, smack, SMACK_LABEL_MAX_LEN, NULL);
	/* FIXME: handle error case if return value is -1 */
	p2 = pid_details(pid);

	if(tidbit_cmp(p1, p2))
	{
		/* pack values into u32 array */

		/* UID fits into a single item */
		tl = CREDS_TL(CREDS_UID, 1);
		list[nr_items++] = tl;
		list[nr_items++] = p1->uid;

		/* GID fits into a single item */
		tl = CREDS_TL(CREDS_GID, 1);
		list[nr_items++] = tl;
		list[nr_items++] = p1->gid;

		/* Kernel capabilities take up 8 octets, so they
		 * fit into two items
		 */
		tl = CREDS_TL(CREDS_CAP, 2);
		list[nr_items++] = tl;
		list[nr_items++] = p1->kcaps[0];
		list[nr_items++] = p1->kcaps[1];

		/* Supplementary groups are variable */
		tl = CREDS_TL(CREDS_GRP, p1->ngroups);
		for (i = 0; i < p1->ngroups; i++)
			list[nr_items++] = p1->grps[i];

		/* Finish with filler, same as in empty case */
		tl = CREDS_TL(CREDS_MAX, initial_list_size - nr_items);
		list[nr_items++] = tl;
	}
	else
	{
		/* create "empty" list, pack that  */
		tl = CREDS_TL(CREDS_MAX, initial_list_size-1);
		list[nr_items++] = tl;
	}

	free(p1);
	free(p2);

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
	long actual = initial_list_size;
	int maxtries = 4;
	do
		{
		creds_t new_handle = (creds_t)realloc(handle, sizeof(*handle) + actual * sizeof(handle->list[0]));
		if (! new_handle)
			{
			/* Memory allocation failure */
			creds_free(handle);
			return NULL;
			}
#ifdef CREDS_AUDIT_LOG
		if (handle == NULL)
			creds_audit_init(new_handle, pid);
#endif
		handle = new_handle;
		handle->list_size = actual;
		handle->actual = actual = creds_proc_get(pid,
				handle->smacklabel, handle->list, handle->list_size);
		/* warnx("max items=%d, returned %ld", handle->list_size, actual); */
		if (actual < 0)
			{
			/* Some error detected */
			errno = -actual;
			creds_free(handle);
			return NULL;
			}
		}
	while (handle->list_size < actual && --maxtries > 0);
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
	return creds_have_p(creds, type, value);
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

    printf("success\n");

	sprintf(short_name, "%X", value);
    printf("short name: %s\n", short_name);
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
	creds_t handle;

	handle = (creds_t)malloc(sizeof(*handle) + length * sizeof(handle->list[0]));
	if (!handle)
		return NULL;
	handle->actual = handle->list_size = length;
	memcpy(handle->list, list, length * sizeof(handle->list[0]));
#ifdef CREDS_AUDIT_LOG
	creds_audit_init(handle, -1);
#endif
	return handle;
}







