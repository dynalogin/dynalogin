/*
 * dynalogin.h
 *
 *  Created on: 23 May 2010
 *      Author: daniel
 *
 *      This is the API describing the services provided
 *      by the dynalogin authentication controller to other
 *      applications
 */

#ifndef DYNALOGIN_H_
#define DYNALOGIN_H_

#include <apr_dso.h>
#include <apr_hash.h>
#include <apr_pools.h>

#include "dynalogin-types.h"
#include "dynalogin-datastore.h"

typedef struct dynalogin_session_t {
	apr_pool_t *pool;
	apr_dso_handle_t *dso_handle;
	dynalogin_datastore_module_t *datasource;
} dynalogin_session_t;

/* Read any system settings, etc */
dynalogin_result_t dynalogin_init(dynalogin_session_t **session,
		apr_pool_t *pool, apr_hash_t *config);

void dynalogin_done(dynalogin_session_t *h);

dynalogin_result_t dynalogin_authenticate
	(dynalogin_session_t *h, const dynalogin_userid_t userid,
			const dynalogin_code_t code);

dynalogin_result_t dynalogin_read_config_from_file(apr_hash_t **config,
		const char *filename, apr_pool_t *pool);

#endif /* DYNALOGIN_H_ */
