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
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <ctype.h>
#include <sys/creds.h>

/*
 * Retrieve the credentials of another task (or self)
 * print out the list of credentials to standart
 * output, one credential value on each line.
 *
 * creds-get
 *    - output credentials of the current process
 * creds-get -p pid
 *    - output credentials of the selected process
 */
int main(int argc, char **argv)
{
	creds_t creds = creds_init();
	const char *arg;
	const char *match = NULL;
	char buf[200];
	while ((arg = *++argv) != NULL && --argc > 0) {
		int option;
		const char *str;

		if (*arg != '-')
			break;
		++arg;
		while ((option = *arg++) != 0) {
			switch (option) {
			case 'p':
				/* Reload creds from a task */
				str = arg;
				if (*str == 0 && argc > 1) {
					str = *++argv;
					--argc;
				}
				option = atoi(str);
				printf("Retrieving credentials for pid: %d\n", option);
				creds_free(creds);
				creds = creds_gettask(option);
				if (!creds) {
					printf("creds not found for pid: %d\n", option);
					exit(EXIT_FAILURE);
				}
				goto next_arg;
			case 'm':
				match = arg;
				if (*match == 0 && argc > 1) {
					match = *++argv;
					--argc;
				goto next_arg;
				}

			default:
				warnx(
					"Unknown option '%c'\n"
					"\tUsage: creds-get [-p pid] [-m match]\n",
					option);
				exit(EXIT_FAILURE);
			}
		}
	next_arg:
		;
	}
	if (!creds)
		creds = creds_gettask(0);

	if (match)
		{
		int res = creds_find(creds, match, buf, sizeof(buf));
		if (res < 0)
			printf("creds_find failed %d with match %s\n", res, match);
		else if (res >= sizeof(buf))
			printf("creds_find failed -- buf too short for %.*s\n", sizeof(buf), buf);
		else
			printf("%s\n", buf);
		}
	else
		{
		creds_value_t value;
		creds_type_t type;
		int index;


		for (index = 0; (type = creds_list(creds, index, &value)) != CREDS_BAD; ++index) {
			(void)creds_creds2str(type, value, buf, sizeof(buf));
			buf[sizeof(buf)-1] = 0;
			printf("%s\n", buf);
			}
		}
	creds_free(creds);
	exit(EXIT_SUCCESS);
}
