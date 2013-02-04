/*
 * dynalogin.h
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
			dynalogin_scheme_t scheme, const dynalogin_code_t code);

dynalogin_result_t dynalogin_authenticate_digest
        (dynalogin_session_t *h, const dynalogin_userid_t userid,
        	dynalogin_scheme_t scheme, const char *response, const char *realm,
			const char *digest_suffix);

dynalogin_result_t dynalogin_read_config_from_file(apr_hash_t **config,
		const char *filename, apr_pool_t *pool);

dynalogin_scheme_t get_scheme_by_name(const char *scheme_name);
const char *get_scheme_name(dynalogin_scheme_t scheme);

#endif /* DYNALOGIN_H_ */
