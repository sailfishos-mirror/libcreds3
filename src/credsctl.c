/*
 * This file is part of AEGIS
 *
 * Copyright (C) 2009 Nokia Corporation
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

#define _ISOC99_SOURCE /* ..to get isblank from ctype.h */
#define _GNU_SOURCE /* ..to get struct ucred from sys/socket.h */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "creds_fallback.h"

#ifndef CREDS_BAD
#define CREDS_BAD -1
#endif


/* the "/proc/<pid>/status" only includes NGROUPS_SMALL number of
   supplementary groups. This value is not exported from kernel?
   Assume it is 32 (based on 2.6.24 kernel code), and define it here..
*/
#define NGROUPS_SMALL 32



/*
 * Static mapping of capability names <-> values
 *
 * NOTE: The problem with this is that the capability list
 * is determined by the kernel of the package builder,
 * and not by the real kernel where this library
 * is installed!
 */
#define CAP_STRING(s) { s, sizeof(s)-1 }
static const struct {
	const char *const str;
	size_t len;
} cap_names[] = {
#include "cap_names.h"
};

enum {
	STATUS_UID,
	STATUS_GID,
	STATUS_GROUPS,
	STATUS_CAPPRM,
	STATUS_CAPINH,
	STATUS_CAPEFF,
	STATUS_MAX
};


struct stream_buf {
	int fd;
	int eol;
	int head;
	int tail;
	char data[200];
};

#define STRING(s) { s, sizeof(s)-1 }

/* Labels for extacting stuff from proc status */
static const struct {
	const char *prefix;
	size_t len;
} grok[STATUS_MAX] = {
	[STATUS_UID] = STRING("Uid:"),
	[STATUS_GID] = STRING("Gid:"),
	[STATUS_GROUPS] = STRING("Groups:"),
	[STATUS_CAPINH] = STRING("CapInh:"),
	[STATUS_CAPPRM] = STRING("CapPrm:"),
	[STATUS_CAPEFF] = STRING("CapEff:"),
};

static int pull(struct stream_buf *buf, int req_len)
{
	int len;
	while ((len = buf->tail - buf->head) < req_len) {
		int room;
		if (buf->head > 0) {
			if (len > 0)
				memmove(buf->data, buf->data + buf->head, len);
			buf->head = 0;
			buf->tail = len;
		}
		if (buf->fd < 0)
			return 0; /* No data */

		room = sizeof(buf->data) - buf->tail;
		len = read(buf->fd, buf->data + buf->tail, room);
		if (len <= 0) {
			/* No more data available */
			close(buf->fd);
			buf->fd = -1;
			return 0;
		}
		buf->tail += len;
	}
	return len;
}

static void skip_line(struct stream_buf *buf)
{
	int len;
	while ((len = pull(buf, 1)) > 0) {
		char *s = buf->data + buf->head;
		char *nl = memchr(s, '\n', len);
		if (nl) {
			len = nl - s;
			buf->eol = 0;
			buf->head += len + 1;
			return;
		}
		buf->head += len;
	}
	/* ...missing new line at end of file? */
	buf->eol = 1;
}

static void skip_blank(struct stream_buf *buf)
{
	while (pull(buf, 1)) {
		const int c = buf->data[buf->head];
		if (c == '\n') {
			buf->eol = 1;
			break;
		}
		if (!isblank(c))
			break;
		buf->head += 1;
	}
}

static int get_next_int(struct stream_buf *buf)
{
	int good = 0;
	int value = 0;
	
	if (buf->eol)
		return CREDS_BAD;
	
	skip_blank(buf);
	
	/* Pull decimal digits */
	while (pull(buf, 1)) {
		const int c = buf->data[buf->head];
		if (!isdigit(c))
			break;
		value = value * 10 + c - '0';
		buf->head += 1;
		good = 1;
	}
	return good ? value : CREDS_BAD;
}

static int get_cap_bits(struct stream_buf *buf, __u32 *bits, size_t max_bits)
{
	int cap = 0;
	int count = 0;
	char *ptr;
	
	skip_blank(buf);
	if (buf->eol) {
		errno = EINVAL;
		return -1; /* There should always be something! */
	}

	/* The caps is a hex string of undefined length, although currently 16, of
	   which only 32 lowest bits can be set. Need to parse in reverse, to find the
	   capability bit numbers. This should work with any number of capabilities.
	   [Code does not rely on any specific integer size for the hex string,
	   because the hex string is not converted to single number...]
	*/

	/* Find the length of the hex string */
	while (pull(buf, count + 1)) {
		const int c = buf->data[buf->head + count];
		/* Just allow blanks within hex digits, in case someone decides
		   to group the hex digits somehow... */
		if (!isxdigit(c) && !isblank(c))
			break; /* Not hex nor blank! */
		++count;
	}

	ptr = buf->data + buf->head + count;
	buf->head += count;
	while (--count >= 0) {
		int i = 4;
		int c = *--ptr;
		unsigned int nibble;
		if (isblank(c))
			continue; /* Ignore blanks */
		c = tolower(c);
		nibble = isdigit(c) ? c - '0' : 10 + c - 'a';
		while (--i >= 0) {
			if ((nibble & 1) && cap < max_bits)
				bits[cap / 32] |= 1 << (cap % 32);
			nibble >>= 1;
			cap++;
		}
	}
	return 0; /* Success */
}

/**
 * Since this is now used directly from creds.c make the function public
 */
int fallback_get(pid_t pid, __u32 *list, size_t list_length)
{
	struct stream_buf buf;
	size_t index = 0;
	int value;

	buf.head = 0;
	buf.tail = 0;
	buf.eol = 0;

	/* borrow the buf.data for the filename */
	if (pid)
		snprintf(buf.data, sizeof(buf.data), "/proc/%d/status", pid);
	else
		strncpy(buf.data, "/proc/self/status", sizeof(buf.data));
	buf.fd = open(buf.data, O_RDONLY);
	if (buf.fd < 0)
		return -errno;

	while (pull(&buf, 1)) {
		int i;
		__u32 *tl = NULL;
		/* Determine the type of the line */
		for (i = 0; i < STATUS_MAX; ++i) {
			if (pull(&buf, grok[i].len) && memcmp(grok[i].prefix, buf.data + buf.head, grok[i].len) == 0) {
				// Matched the keyword...
				buf.head += grok[i].len;
				break;
			}
		}
		
		/* Handle the line content */
		switch (i) {
		case STATUS_UID:
			value = get_next_int(&buf); /* Skip uid */
			value = get_next_int(&buf); /* Get effective uid */
			index += 2;
			if (index <= list_length) {
				list[0] = CREDS_TL(CREDS_UID, 1);
				list[1] = value;
				list += 2;
			}
			break;
		case STATUS_GID:
			value = get_next_int(&buf); /* Skip gid */
			value = get_next_int(&buf); /* Get effective gid */
			index += 2;
			if (index <= list_length) {
				list[0] = CREDS_TL(CREDS_GID, 1);
				list[1] = value;
				list += 2;
			}
			break;
		case STATUS_GROUPS:
			index += 1;
			if (index <= list_length) {
				list[0] = CREDS_TL(CREDS_GRP, 0);
				tl = &list[0];
				list += 1;
			}
			do {
				skip_blank(&buf);
				if (buf.eol)
					break;
				if (index < list_length) {
					value = get_next_int(&buf);
					list[0] = value;
					*tl = CREDS_TL(CREDS_TLV_T(*tl), CREDS_TLV_L(*tl) + 1);
					list += 1;
				}
				++index;
			} while (1);
			break;
		case STATUS_CAPEFF:
			index += 3;
			if (index <= list_length) {
				list[0] = CREDS_TL(CREDS_CAP, 2);
				list[1] = 0;
				list[2] = 0;
				if (get_cap_bits(&buf, &list[1], 64))
					goto out;
				list += 3;
			}
			break;
		default:
			break;
		}
		/* Skip over to the beginning of the next line */
		skip_line(&buf);
	}
	if (buf.fd >= 0)
		close(buf.fd);
	return index;
	
out:
	/* Detetected an error, do not silently return incomplete data! */

	if (buf.fd >= 0)
		close(buf.fd);
	return 0;
}


static long fallback_str2creds(const char *str, long *value)
{
	static const struct {const char *const str; size_t len; } prefix = CAP_STRING("CAP::");

	size_t str_len;
	int i;
	if (!str)
		return CREDS_BAD;

	str_len = strlen(str);
	if (str_len < prefix.len || memcmp(prefix.str, str, prefix.len) != 0)
		return CREDS_BAD;
	/* Skip over the "CAP::" before matching capability name */
	str_len -= prefix.len;
	str += prefix.len;

	for (i = 0; i < sizeof(cap_names) / sizeof(cap_names[0]); ++i)
		if (cap_names[i].len == str_len &&
		    memcmp(cap_names[i].str, str, str_len) == 0) {
			*value = i;
			return CREDS_CAP;
		}
	return CREDS_BAD;
}

static long fallback_creds2str(int type, long value, char *str, size_t str_len)
{
	if (type == CREDS_CAP) {
		if (value >= 0 &&
		    value < sizeof(cap_names) / sizeof(cap_names[0]) &&
		    cap_names[value].str)
			return snprintf(str, str_len, "CAP::%s", cap_names[value].str);
		else
			return snprintf(str, str_len, "CAP::%ld", value);
	}
	return -1;
}


#if HAVE_LINUX_AEGIS_CREDS_H

static const char *const policy_file = "/sys/kernel/security/" CREDS_SECURITY_DIR "/" CREDS_SECURITY_FILE;

long creds_kstr2creds(const char *str, long *value)
{
	const int fd = open(policy_file, O_RDONLY);
	if (fd >= 0) {
	        union creds_ioc_arg arg = {
			.str.type = -1,
			.str.length = strlen (str),
			.str.value = value,
			.str.name = (char *)str,
		};
		const long result = ioctl(fd, SIOCCREDS_STR2CREDS, &arg);
		close(fd);
		return result;
	}
	return fallback_str2creds(str, value);
}

long creds_kcreds2str(int type, long value, char *str, size_t str_len)
{
	const int fd = open(policy_file, O_RDONLY);
	if (fd >= 0) {
		union creds_ioc_arg arg = {
			.str.type = type,
			.str.length = str_len,
			.str.value = &value,
			.str.name = str,
		};
		const long result = ioctl(fd, SIOCCREDS_CREDS2STR, &arg);
		close(fd);
		return result;
	}
	return fallback_creds2str(type, value, str, str_len);
}

long creds_kget(pid_t pid, __u32 *list, size_t list_length)
{
	const int fd = open(policy_file, O_RDONLY);
	if (fd >= 0) {
		union creds_ioc_arg arg = {
			.list.pid = pid,
			.list.length = list_length,
			.list.items = list,
		};
		const long result = ioctl(fd, SIOCCREDS_GET, &arg);
		close(fd);
		return result;
	}
	return fallback_get(pid, list, list_length);
}
#else

long creds_kget(pid_t pid, __u32 *list, size_t list_length)
{
	return fallback_get(pid, list, list_length);
}

long creds_kstr2creds(const char *str, long *value)
{
	return fallback_str2creds(str, value);
}

long creds_kcreds2str(int type, long value, char *str, size_t str_len)
{
	return fallback_creds2str(type, value, str, str_len);
}

#endif
