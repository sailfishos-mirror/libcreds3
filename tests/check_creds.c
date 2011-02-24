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
#include <creds_fallback.h>

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

START_TEST(test_gettask)
{
	SmackmanContext ctx;
	creds_value_t value;
	creds_type_t type;
	int ret;
	char buf[200];
	mode_t mode;
	FILE *fp;
	const char *sn;
	creds_t cr;
	int index;
	int ok = 0;

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
	sn = smackman_to_short_name(ctx, "Banana");

	smackman_save(ctx);
	smackman_free(ctx);

	ctx = smackman_new("load", "labels");
	ck_assert_msg(ctx != NULL, "SmackmanContext not created for non-existing labels file");
	if (ctx == NULL)
		return;

	fp = fopen("/proc/self/attr/current", "w");
	sn = smackman_to_short_name(ctx, "Banana");
	fprintf(fp, "%s", sn);
	fclose(fp);

	smackman_free(ctx);

	cr = creds_gettask(0);
	ck_assert_msg(cr != NULL, "Couldn't get creds for self.");
	if (cr == NULL)
		return;

	for (index = 0; (type = creds_list(cr, index, &value)) != CREDS_BAD; ++index) {
		if (type != CREDS_SMACK)
			continue;

		ck_assert_msg(!ok, "Duplicate security context.");
		if (ok) {
			ok = 0;
			break;
		}

		ok = creds_creds2str(type, value, buf, sizeof(buf));
		ck_assert_msg(ok >= 0, "Conversion failed for SM-%08X\n", value);
		if (ok < 0) {
			ok = 0;
			break;
		}

		buf[sizeof(buf)-1] = 0;
		ok =  strcmp("SMACK::Banana", buf) == 0;
		ck_assert_msg(ok, "Invalid long name %s", buf);
		if (!ok)
			break;
	}

	creds_free(cr);
	ck_assert_msg(ok, "Security context not succesfully retrieved.");
}
END_TEST

START_TEST(test_have_access)
{
	SmackmanContext ctx;
	creds_value_t value;
	creds_type_t type;
	int ret;
	char buf[200];
	mode_t mode;
	FILE *fp;
	const char *sn;
	creds_t cr;

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

	ctx = smackman_new("load", "labels");
	ck_assert_msg(ctx != NULL, "SmackmanContext not created for non-existing labels file");
	if (ctx == NULL)
		return;

	fp = fopen("/proc/self/attr/current", "w");
	sn = smackman_to_short_name(ctx, "Banana");
	fprintf(fp, "%s", sn);
	fclose(fp);

	smackman_free(ctx);

	cr = creds_gettask(0);
	ck_assert_msg(cr != NULL, "Couldn't get creds for self.");
	if (cr == NULL)
		return;

	creds_str2creds("SMACK::Peach", &value);
	ret = creds_have_access(cr, CREDS_SMACK, value, "a");
	ck_assert_msg(ret == 1, "No access");

	creds_str2creds("SMACK::Peach", &value);
	ret = creds_have_access(cr, CREDS_SMACK, value, "ax");
	ck_assert_msg(ret == 1, "No access");

	creds_str2creds("SMACK::Peach", &value);
	ret = creds_have_access(cr, CREDS_SMACK, value, "wax");
	ck_assert_msg(ret == 0, "Access");

	creds_str2creds("SMACK::Orange", &value);
	ret = creds_have_access(cr, CREDS_SMACK, value, "r");
	ck_assert_msg(ret == 0, "Access");

	creds_free(cr);
}
END_TEST

START_TEST(test_set_creds)
{
	creds_t cr;
	creds_value_t value;
	creds_type_t type = CREDS_GRP;
	char buf[512];
	int ret, i;
	cr = creds_gettask(0);
	ck_assert_msg(cr != NULL, "Couldn't get creds for self.");
	if (cr == NULL)
		return;

	while (type != CREDS_BAD) {
		for (i = 0; (type = creds_list(cr, i, &value)) != CREDS_BAD; ++i) {
			if (type != CREDS_GRP)
				continue;
			creds_sub(cr, type, value);
			break;
		}
	}

	ret = creds_set(cr);
	ck_assert_msg(ret >= 0, "creds_set failed");
	creds_free(cr);

	cr = creds_gettask(0);
	ck_assert_msg(cr != NULL, "Couldn't get creds for self.");
	if (cr == NULL)
		return;

	while (type != CREDS_BAD)
		for (i = 0; (type = creds_list(cr, i, &value)) != CREDS_BAD; ++i)
			ck_assert_msg(type != CREDS_GRP, "Group found although all of them should be removed.");

	creds_free(cr);
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

	s = suite_create("Creds");

	tc_core = tcase_create("Creds");
	tcase_add_test(tc_core, test_str2creds);
	tcase_add_test(tc_core, test_gettask);
	tcase_add_test(tc_core, test_have_access);
	tcase_add_test(tc_core, test_set_creds);
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


