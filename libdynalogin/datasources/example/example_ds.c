/*
 * test_ds.c
 *
 *  Created on: 23 May 2010
 *      Author: daniel
 */

#include <stdio.h>
#include <string.h>

#include <apr_hash.h>

#include "dynalogin-datastore.h"

extern dynalogin_datastore_module_t example_ds_module;

static dynalogin_user_data_t u_tester =
{
		"test2",  // name
		"abc123", // secret
		0, // counter
		0, // failure_count
		0, // locked
		0, // last_success
		0, // last_attempt
		"", // last generated code
		NULL, // password
		NULL // pvt
};

static dynalogin_result_t init(apr_pool_t *pool, apr_hash_t *config)
{
	fprintf(stderr, "test_ds: init\n");
}

static void done(void)
{
}

static void user_fetch(dynalogin_user_data_t **ud,
		const dynalogin_userid_t userid,
		apr_pool_t *pool)
{
	if(strcmp((char *)userid, u_tester.userid) == 0)
		*ud = &u_tester;
	else
		*ud = (dynalogin_user_data_t *)NULL;

	fprintf(stderr, "user = %s, count = %d\n", userid, u_tester.counter);
	return;
}

static void user_update(dynalogin_user_data_t *ud, apr_pool_t *pool)
{
	return;
}

dynalogin_datastore_module_t example_ds_module =
{
		init,
		done,
		NULL, // user_add
		NULL, // user_delete
		NULL, // user_update_secret
		user_fetch, // user_fetch
		user_update, // user_update
		NULL,
		NULL  // dynalogin_pvt - used by libdynalogin
};
