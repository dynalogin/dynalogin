/*
 * fs_ds.c
 *
 *  File format:
 *      userid:scheme:secret:counter:failure-count:
 *          locked:last_success:last_attempt:last_code
 *
 *  Potential improvements:
 *   - only return a copy of the user data, rather than the data itself,
 *     so that the app can't modify the contents of the array
 *   - write to a temporary file and then move on top of the original
 *   - user lifecycle (add user, delete user, etc)
 *   - file locking
 *   - cache the file in RAM (with inter-thread locking)
 *   - store counter in a separate file, in binary format
 *     for better performance, reduced locking and concurrent access
 *   - session-based behaviour for each user login
 *   - make an array of pointers rather than an array of structs,
 *     so that hash table can be constructed in the same loop
 */

#define FS_DB LOCALSTATEDIR "/dynalogin-passwd"
#define FS_LINEBUF_LEN 255
#define FS_FIELD_SEP ":"
#define ERRBUFLEN 1024

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <apr_file_io.h>
#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include "dynalogin.h"
#include "dynalogin-datastore.h"

#define FIELD_COUNT 9

extern dynalogin_datastore_module_t fs_ds_module;

typedef struct fs_user_t {
	struct fs_user_t *next;

} fs_user_t;

static dynalogin_result_t init(apr_pool_t *pool, apr_hash_t *config)
{
	syslog(LOG_INFO, "fs_ds: init");
}

static void done(void)
{
}

apr_status_t get_sub_strings(apr_array_header_t **dest,
		const char *s, const char *sep,
		apr_pool_t *pool)
{
	apr_array_header_t *_dest;
	char *p, *_copy, *token, **place;
	int i;

	if((_copy = apr_pstrdup(pool, s)) == NULL)
		return APR_ENOMEM;

	if((_dest = apr_array_make(pool, 0, sizeof(char *)))==NULL)
		return APR_ENOMEM;

	token = apr_strtok(_copy, sep, &p);
	for (i = 0;
			token != NULL;
			i++)
	{
		place=apr_array_push(_dest);
		*place=token;
		token = apr_strtok(NULL, sep, &p);
	}

	*dest = _dest;
	return APR_SUCCESS;
}

apr_status_t parse_user(dynalogin_user_data_t *user_data, const char *user_record,
		apr_pool_t *pool)
{
	char *p, **_substrings;
	apr_array_header_t *_substrings_r;
	apr_status_t res;
	int field;

	bzero(user_data, sizeof(dynalogin_user_data_t));

	user_data->pvt = (fs_user_t*)apr_pcalloc(pool, sizeof(fs_user_t));
	if(user_data->pvt == NULL)
		return APR_ENOMEM;

	if((res=get_sub_strings(&_substrings_r, user_record, FS_FIELD_SEP, pool))
			!= APR_SUCCESS)
		return res;

	if(_substrings_r->nelts != FIELD_COUNT)
		return APR_EGENERAL;

	_substrings=(char **)_substrings_r->elts;

	field = 0;
	user_data->userid=_substrings[field++];
	user_data->scheme = get_scheme_by_name(_substrings[field++]);
	user_data->secret=_substrings[field++];
	user_data->counter=atoi(_substrings[field++]);
	user_data->failure_count=atoi(_substrings[field++]);
	user_data->locked=atoi(_substrings[field++]);
	user_data->last_success=atol(_substrings[field++]);
	user_data->last_attempt=atol(_substrings[field++]);
	user_data->last_code=_substrings[field++];
}

apr_status_t load_users(apr_array_header_t **users,
		apr_hash_t **users_map,
		const char *file_name,
		apr_pool_t *pool)
{
	apr_status_t res;
	apr_file_t *f;
	apr_array_header_t *_users;
	apr_hash_t *_users_map;
	dynalogin_user_data_t *u;
	char buf[FS_LINEBUF_LEN + 1];
	size_t len;

	if((_users=apr_array_make(pool, 0, sizeof(dynalogin_user_data_t)))==NULL)
		return APR_ENOMEM;

	if((_users_map=apr_hash_make(pool)) == NULL)
		return APR_ENOMEM;

	if(res=apr_file_open(&f, file_name, APR_READ | APR_SHARELOCK, 0, pool)
			!= APR_SUCCESS)
		return res;

	while(apr_file_gets(buf, FS_LINEBUF_LEN, f) == APR_SUCCESS)
	{
		len = strlen(buf);
		if(len > 0 && buf[len-1]=='\n')
			buf[len-1] = 0;

		u=(dynalogin_user_data_t *)apr_array_push(_users);
		if((res=parse_user(u, buf, pool))!=APR_SUCCESS)
		{
			apr_file_close(f);
			return res;
		}
	}

	apr_file_close(f);

	/* Mark the end of the array with userid = NULL */
	u=apr_array_push(_users);
	bzero(u, sizeof(dynalogin_user_data_t));
	/* NULL is not 0 on every platform, so set it explicitly */
	u->userid = NULL;

	/* Build the hash table */
	for( u = (dynalogin_user_data_t *)_users->elts;
			u->userid != NULL;
			u++)
		apr_hash_set(_users_map, u->userid, APR_HASH_KEY_STRING, u);

	*users = _users;
	*users_map = _users_map;

	return APR_SUCCESS;
}

apr_status_t store_users(apr_array_header_t *users,
		const char *file_name,
		apr_pool_t *pool)
{
	apr_pool_t *_pool;
	apr_status_t res;
	apr_file_t *f;
	dynalogin_user_data_t *u;
	int i;
	char *s;

	if((res = apr_pool_create(&_pool, pool)) != APR_SUCCESS)
		return res;

	if(res=apr_file_open(&f, file_name,
			APR_WRITE | APR_SHARELOCK | APR_TRUNCATE,
			0, _pool)
			!= APR_SUCCESS)
	{
		apr_pool_destroy(_pool);
		return res;
	}

	i = 0;
	for(u = (dynalogin_user_data_t *)(users->elts);
			i < users->nelts && u[i].userid != NULL;
			i++)
	{
		s = apr_psprintf(_pool, "%s:%s:%s:%d:%d:%d:%ld:%ld:%s\n",
				u[i].userid, get_scheme_name(u[i].scheme), u[i].secret,
				u[i].counter, u[i].failure_count, u[i].locked,
				u[i].last_success, u[i].last_attempt,
				u[i].last_code);
		syslog(LOG_DEBUG, "writing: %s", s);

		if((res=apr_file_puts(s, f))!=APR_SUCCESS)
		{
			apr_file_close(f);
			apr_pool_destroy(_pool);
			return res;
		}
	}

	apr_file_close(f);
	apr_pool_destroy(_pool);

	return APR_SUCCESS;
}

static void user_fetch(dynalogin_user_data_t **ud, const dynalogin_userid_t userid,
		apr_pool_t *pool)
{
	apr_array_header_t *users;
	apr_hash_t *users_map;

	dynalogin_user_data_t *_ud;

	*ud = NULL;

	if(userid == NULL)
		return;

	if(load_users(&users, &users_map, FS_DB, pool)!=APR_SUCCESS)
		return;

	_ud = (dynalogin_user_data_t *)apr_hash_get(users_map, (char *)userid,
			APR_HASH_KEY_STRING);

	if(_ud != NULL)
	{
		*ud = _ud;
		syslog(LOG_DEBUG, "user = %s, count = %d", userid, (*ud)->counter);
	}
	return;
}

static void user_update(dynalogin_user_data_t *ud, apr_pool_t *pool)
{
	apr_array_header_t *users;
	apr_hash_t *users_map;

	dynalogin_user_data_t *_ud;

	apr_status_t res;

	char errbuf[ERRBUFLEN + 1];

	_ud = NULL;

	if(ud == NULL || ud->userid == NULL)
		return;

	if(load_users(&users, &users_map, FS_DB, pool)!=APR_SUCCESS)
		return;

	_ud = (dynalogin_user_data_t *)apr_hash_get(users_map,
			(char *)(ud->userid),
			APR_HASH_KEY_STRING);

	if(_ud != NULL)
	{
		_ud->counter = ud->counter;
		syslog(LOG_DEBUG, "user = %s, count = %d", _ud->userid, _ud->counter);
		if((res=store_users(users, FS_DB, pool))!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "unexpected result while writing users file: %s",
							apr_strerror(res, errbuf, ERRBUFLEN));
		}
	}

	return;
}

dynalogin_datastore_module_t fs_ds_module =
{
		init,
		done,
		NULL, // user_add
		NULL, // user_delete
		NULL, // user_update_secret
		user_fetch, // user_fetch
		user_update, // user_update
		NULL,  // mod_pvt
		NULL  // dynalogin_pvt - used by libdynalogin
};
