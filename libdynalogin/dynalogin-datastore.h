/*
 * dynalogin-datastore.h
 *
 *      This is the API between the datastore module
 *      and the dynalogin authentication controller
 */

#ifndef DYNALOGINDATASTORE_H_
#define DYNALOGINDATASTORE_H_

#include <time.h>

#include <apr_hash.h>
#include <apr_pools.h>

#include "dynalogin-types.h"

typedef struct dynalogin_user_data {
	dynalogin_userid_t userid;
	dynalogin_scheme_t scheme;
	dynalogin_secret_t secret;
	dynalogin_counter_t counter;
	int failure_count;
	int locked;
	time_t last_success;
	time_t last_attempt;
	dynalogin_code_t last_code;  /* Last code generated on server */
	char *password;     /* Optional password that should enter as a
							prefix in front of the code */
	void *pvt; /* Private pointer for use by the datastore module */
} dynalogin_user_data_t;

typedef struct dynalogin_datastore_module {
	/* Module lifecycle - the provider is not obliged to implement */
	/* @param pool the pool to use for allocations that last longer than a
	 *             single fetch
	 * @param config the configuration of the dynalogin stack
	 */
	dynalogin_result_t (*init)(apr_pool_t *pool, apr_hash_t *config);
	void (*done)();

	/* User management - the provider is not obliged to implement */
	int (*user_add)(void);
	void (*user_delete)(void);
	void (*user_update_secret)();

	/* Authentication process - the provider is obliged to implement */
	void (*user_fetch)
	  (dynalogin_user_data_t **ud, const dynalogin_userid_t userid,
			  apr_pool_t *pool);
	void (*user_update)(dynalogin_user_data_t *ud, apr_pool_t *pool);

	/* Reserved for use by the module */
	void *mod_pvt;
	/* Reserved for use by the dynalogin stack */
	void *dynalogin_pvt;

} dynalogin_datastore_module_t;

#endif /* DYNALOGINDATASTORE_H_ */
