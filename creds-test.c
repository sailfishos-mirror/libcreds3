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
 * A simple test program to check the basic library functionality
 */
int main(int argc, char **argv)
{
    int ret;
	char buf[200];
	while (--argc > 0) {
		creds_value_t value;
		creds_type_t type = creds_str2creds(argv[argc], &value);
		ret = creds_creds2str(type, value, buf, sizeof(buf));
		if (ret < 0) {
			printf("Cannot convert %d to string\n", value);
			return EXIT_FAILURE;
		}
		buf[sizeof(buf)-1] = 0;
		printf("%s translates to %s = %ld\n", argv[argc], buf, value);
	}
	exit(EXIT_SUCCESS);
}
