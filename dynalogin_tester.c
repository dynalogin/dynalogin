/*
 * dynalogin_tester.c
 *
 *  Created on: 23 May 2010
 *      Author: daniel
 */

#include <stdio.h>
#include <stdlib.h>

#include "dynalogin.h"

/* #define MY_DS "fs_ds" */
#define MY_DS "odbc_ds"

#define MAX_CODE 32

int main(int argc, char *argv[])
{
	dynalogin_userid_t userid;
	char code_buf[MAX_CODE];
	dynalogin_code_t code = (dynalogin_code_t)code_buf;
	dynalogin_session_t *h;
	dynalogin_result_t res;

	apr_pool_t *pool;
	apr_hash_t *config;

	if(apr_initialize() != APR_SUCCESS)
	{
		fprintf(stderr, "apr_initialize failed\n");
		return 1;
	}

	if(argc != 2)
	{
		fprintf(stderr, "Must specify a user ID\n");
		return 1;
	}
	userid = (dynalogin_userid_t)argv[1];

	if(apr_pool_create(&pool, NULL) != APR_SUCCESS)
	{
		return 1;
	}
	if((config = apr_hash_make(pool)) == NULL)
	{
		return 1;
	}
	apr_hash_set(config, "dynalogin.datasource",
			APR_HASH_KEY_STRING, MY_DS);

	fprintf(stderr, "Trying to initialise the stack...\n");
	if(dynalogin_init(&h, pool, config) != DYNALOGIN_SUCCESS)
	{
		fprintf(stderr, "Failed to initialise dynalogin\n");
		return 1;
	}

	while(1)
	{
		printf("Enter the code for %s: ", (char *)userid);
		scanf("%s", code_buf);
		printf("\nYou entered code [%s].\n", code_buf);

		res = dynalogin_authenticate(h, userid, code);

		switch(res)
		{
		case DYNALOGIN_SUCCESS:
			printf("Authentication success\n");
			break;
		case DYNALOGIN_DENY:
			printf("Authentication denied\n");
			break;
		case DYNALOGIN_ERROR:
			printf("Error processing the request\n");
			break;
		default:
			printf("Unexpected result\n");
		}
	}

	return 0;
}
