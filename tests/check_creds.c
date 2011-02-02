/*
 * This file is part of libcreds
 *
 * Copyright (C) 2010 Nokia Corporation
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
 * Author: Jarkko Sakkinen <ext-jarkko.2.sakkinen@nokia.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <creds.h>
#include <sched.h>
#include <syscall.h>
#include <unistd.h>
#include <smackman.h>

START_TEST(test_str2creds)
{
	SmackmanContext ctx;
	creds_value_t value;
	creds_type_t type;
	int ret;
	char buf[200];
	mode_t mode;

	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	unlink("labels");
	creat("labels", mode);

	unlink("load");
	creat("load", mode);

	ctx = smackman_new("load", "labels");
	ck_assert_msg(ctx != NULL, "SmackmanContext not created for non-existing labels file");
	if (ctx == NULL)
		return;

	smackman_add(ctx, "Apple", "Orange", "rwx");
	smackman_add(ctx, "Plum", "Peach", "rx");
	smackman_add(ctx, "Banana", "Peach", "xa");

	smackman_save(ctx);
	smackman_free(ctx);

	type = creds_str2creds("SMACK::Plum", &value);
	ck_assert_msg(value != -1, "creds_str2creds failed");
	ret = creds_creds2str(type, value, buf, sizeof(buf));
	ck_assert_msg(value != -1, "creds_creds2str failed");

	type = creds_str2creds("SMACK::Peach", &value);
	ck_assert_msg(value != -1, "creds_str2creds failed");
	ret = creds_creds2str(type, value, buf, sizeof(buf));
	ck_assert_msg(value != -1, "creds_creds2str failed");
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;
	int err;

	err = syscall(SYS_unshare, CLONE_NEWNS);
	if (err < 0) {
		perror("unshare");
		return NULL;
	}

	if (system("mount -n --bind . /smack") != 0)
		return NULL;

	if (system("mount -n --bind . /etc/smack") != 0)
		return NULL;

	fprintf(stderr, "virtual /etc/smack:\n");
	system("ls -1 /etc/smack 1>&2");
	fprintf(stderr, "virtual /smack:\n");
	system("ls -1 /smack 1>&2");

	s = suite_create("Creds");

	tc_core = tcase_create("Creds");
	tcase_add_test(tc_core, test_str2creds);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int nfailed;
	Suite *s = ruleset_suite();
	if (s == NULL) {
		fprintf(stderr, "failed to create the test suite\n");
		return EXIT_FAILURE;
	}

	SRunner *sr = srunner_create(s);
	srunner_set_log(sr, "check_creds.log");
	srunner_run_all(sr, CK_ENV);
	nfailed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


