/*
 * This file is part of libcreds.
 *
 * Copyright (C) 2009 Nokia Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*!
 * @file creds.h
 *
 * Credentials handling library.
 *
 * The current credentials information supported by the kernel,
 * includes following:
 *
 * - user id, names defined by /etc/passwd
 * - group id, names defined by /etc/group
 * - capabilities, names defined by the kernel
 * - supplementary groups, names defined by /etc/group
 *
 * - Libcreds3 allows to handle smack labels in addition to the previous set
 *
 * When available, the kernel defines the supported credential types
 * (CREDS_* constants) in <linux/aegis/creds.h>.
 *
 * Most users of this API need to be aware of only one symbol:
 * CREDS_BAD.
 */


#ifndef _SYS_CREDS_H
#define _SYS_CREDS_H

#include <sys/types.h>
#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*!
 * Types of credentials information
 */
typedef int creds_type_t;

#define CREDS_BAD	-1	/* Indicates error */

/*!
 * Value of the credential
 */
typedef long creds_value_t;

/*!
 * Opaque credentials handle.
 *
 * The internal structure is defined by the implementation.  A NULL
 * value is also valid, and represents an empty credentials set. All
 * functions defined here, that take creds_t as a parameter, can be
 * called with NULL handle.
 */
typedef struct _creds_struct *creds_t;


/*!
 * Read peer credentials from a socket.
 *
 * @param socket The socket
 * @return a handle for the credentials
 *
 * The returned handle must be freed with creds_free.
 *
 * Because every peer has at least UID and GID, empty credentials set
 * (a NULL return) indicates some error.
 */
creds_t creds_getpeer(int socket);

/*!
 * Read credentials from a task
 *
 * @param pid The process id (0 gives current process)
 * @return a handle for the credentials
 *
 * The returned handle must be freed with creds_free.
 *
 * Because every task has at least UID and GID, empty credentials set
 * (a NULL return) indicates some error.
 */
creds_t creds_gettask(pid_t pid);

/*!
 * Initialize a new empty credentials handle
 *
 * @return the handle.
 *
 * This operation succeeds always. The returned value
 * must be released with creds_free.
 *
 * Note: because a NULL handle is a valid representation of an empty
 * credentials set, implementation may just return NULL here (and NULL
 * return is not an indication of any error!).
 */
creds_t creds_init();

/*!
 * Clear all credentials.
 *
 * @param creds The credentials handle.
 *
 * Clear out all credentials from creds, without
 * releasing the memory space allocated to the
 * handle.
 */
void creds_clear(creds_t creds);

/*!
 * Free credentials handle.
 *
 * @param creds The credentials handle.
 *
 * After the call, the content of the handle is invalid and must not
 * be passed to any of the functions in this header. To be resused,
 * reinitialize the handle with one of the following functions:
 *
 * - creds_init
 * - creds_gettask
 * - creds_getpeer
 */
void creds_free(creds_t creds);


/*!
 * Iterate over all credentials values.
 *
 * @param creds The credentials handle.
 * @param index The index of the credential [0..N]
 * @param value The returned credentials value
 * @return type of the credential value, or CREDS_BAD when no more.
 */
creds_type_t creds_list(const creds_t creds, int index, creds_value_t *value);

/*!
 * Find first credential matching a pattern
 *
 * @param creds The credentials handle
 * @param pattern The pattern to match ('*' match zero or more, '?' match single)
 * @param buf The buffer for the matched credential
 * @param size The size of the buffer
 * @return Total length of the matched string (or -1)
 *
 * The return value has the semantics of 'snprintf'. If the return
 * value is larger or equal to size, the provided buffer was too short
 * and find has failed.
 *
 * The return value has following interpretaions
 *
 * - success return (>= 0 and < size)
 * - failed return -1, no match or bad parameters in call
 * - failed return >= size, buffer too small
 *
 * Example, to find user id from credentials
 *    creds_find(creds, "UID::*", buf, sizeof(buf));
 */
int creds_find(const creds_t creds, const char *pattern, char *buf, size_t size);

/*!
 * Test presence of a credential.
 *
 * @param creds The credentials handle
 * @param type The type of credentials to test
 * @param value The specific value to test
 * @return 1, if credential is present, and 0 otherwise.
 */
int creds_have_p(const creds_t creds, creds_type_t type, creds_value_t value);


/*!
 * Test if the process with a given credential set can perform an access of specified type on a object protected by the credential 
 * identified by type and value.
 *
 * @param creds The credentials handle
 * @param type The type of credentials to test
 * @param value The specific value to test
 * @param access_type The access type
 * @return 1, if access is allowed, and 0 otherwise.
 *
 * Examples of access_type valid strings: "r", "w", "rw", "a", "ra", "wa", "x", "rwx", and etc.
 * If an empty string is supplied, then access is assumed to be "rw".
 */
int creds_have_access(const creds_t creds, creds_type_t type, creds_value_t value, const char *access_type);

/*!
 * Universal string to credential conversion
 *
 * @param credential The name
 * @retval value The credential value (NULL possible)
 * @return credential type or CREDS_BAD, if conversion failed.
 *
 * The credential string starts with a name space designation
 * separated from the actual credential name by "::". Some possible
 * name spaces on a Unix platform are
 *
 *   - UID::user_name
 *   - GID::group_name
 *   - GRP::group_name (as supplementary)
 *   - CAP::capability_name
 *
 * Converting a known name space only (for example "GID::")
 * returns the type of the name space and CREDS_BAD as the value.
 *
 * An implementation may support other name spaces depending on
 * platform. It also decides how to deal with omitted namespace.
 *
 * Beware, that although in above, the example name spaces each map
 * directly to unique credential type, other name spaces may map to
 * the same types, e.g. it's not 1-to-1 mapping!
 */
long creds_str2creds(const char *credential, creds_value_t *value);

/*!
 * Universal credential to string conversion
 *
 * @param type Credential type
 * @param value Credential value
 * @param buf The buffer for the converted value
 * @param size The size of the buffer
 * @return Total length of the converted string
 *
 * The return value has the semantics of 'snprintf'. If the return
 * value is larger or equal to size, the provided buffer was too short
 * (and conversion was truncated).
 */
int creds_creds2str(creds_type_t type, creds_value_t value, char *buf, size_t size);

/*!
 * Export opaque credentials information as integer array
 *
 * @param creds Credentials handle
 * @param length Returns the length of the array (# of uint32_t ints)
 * @return Pointer to the first uint32_t
 *
 * The returned value is only valid as long as the creds handle is not
 * modified or freed.
 */
const uint32_t *creds_export(creds_t creds, size_t *length);

/*!
 * Recreate credentails from exported integer array
 *
 * @param list The integer array
 * @param length The length (# of uint32_t) of array
 * @return creds handle
 *
 * The returned creds handle must be released with creds_free.
 */
creds_t creds_import(const uint32_t *list, size_t length);

	
#ifdef	__cplusplus
}
#endif
#endif
