/*
 * odbc_ds.c
 *
 *  TO DO:
 *
 *  - read values from configuration file
 *  - ability to retry after a database error or re-connection
 *  - better error handling
 *    - return values
 *    - logging
 *  - connection pooling
 *  - user-specified queries and table names
 *
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sql.h>
#include <sqlext.h>

#include <apr_hash.h>
#include <apr_pools.h>

#include "dynalogin-datastore.h"

#define DB_DSN "DSN=dynalogin;"

#define DB_SELECT "SELECT id, userid, secret, counter, failure_count, " \
			"locked, last_success, last_attempt, last_code, password " \
			"FROM dynalogin_user WHERE userid = ?"

#define DB_UPDATE "UPDATE dynalogin_user SET counter = ?, failure_count = ?, " \
			"locked = ?, last_success = ?, last_attempt = ?, last_code = ? " \
			"WHERE userid = ?"

extern dynalogin_datastore_module_t odbc_ds_module;

typedef struct odbc_mod_pvt {
	apr_pool_t *pool;
} odbc_mod_pvt_t;

typedef struct odbc_connection {
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT query_stmt;
	SQLHSTMT update_stmt;
	apr_pool_t *pool;
} odbc_connection_t;

static dynalogin_result_t init(apr_pool_t *pool, apr_hash_t *config)
{
	odbc_mod_pvt_t *mp;

	if((mp = apr_pcalloc(pool, sizeof(odbc_mod_pvt_t))) == NULL)
		return DYNALOGIN_ERROR;

	mp->pool = pool;

	odbc_ds_module.mod_pvt = mp;

	return 0;
}

static void done(void)
{
	odbc_mod_pvt_t *mp = (odbc_mod_pvt_t *)odbc_ds_module.mod_pvt;
}

void extract_error(
		char *fn,
		SQLHANDLE handle,
		SQLSMALLINT type, apr_pool_t *pool)
{
	SQLINTEGER i = 0;
	SQLINTEGER native;
	SQLCHAR state[ 7 ];
	SQLCHAR text[256];
	SQLSMALLINT len;
	SQLRETURN ret;

	apr_pool_t *_pool;
	char *errmsg, *errmsgs = NULL;

	if(apr_pool_create(&_pool, pool) != APR_SUCCESS)
	{
		syslog(LOG_CRIT, "unable to allocate memory for SQL error analysis");
		return;
	}

	do
	{
		ret = SQLGetDiagRec(type, handle, ++i, state, &native, text,
				sizeof(text), &len );
		if (SQL_SUCCEEDED(ret))
			errmsg = apr_psprintf(_pool, "[ %s:%ld:%ld:%s ]",
					state, i, native, text);

		if(errmsgs != NULL) {
			errmsgs = apr_pstrcat(_pool, errmsgs, ", ", NULL);
			errmsgs = apr_pstrcat(_pool, errmsgs, errmsg, NULL);
		}
		else
			errmsgs = errmsg;
	}
	while( ret == SQL_SUCCESS );

	syslog(LOG_ERR, "ODBC call %s failed: %s", fn, errmsgs);
	apr_pool_destroy(_pool);
}

apr_status_t odbc_get_string(char **s, SQLHSTMT stmt,
		SQLUSMALLINT col, apr_pool_t *pool)
{
	SQLRETURN ret;
	SQLLEN len;

	*s = NULL;

	ret = SQLGetData(stmt, col, SQL_C_CHAR, NULL, 0, &len);
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	if (len == SQL_NULL_DATA)
		return APR_SUCCESS;

	if((*s = apr_pcalloc(pool, len + 1)) == NULL)
		return APR_EGENERAL;

	ret = SQLGetData(stmt, col, SQL_C_CHAR,
			*s, len + 1, &len);
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	return APR_SUCCESS;
}

apr_status_t odbc_set_string(char *s, SQLHSTMT stmt, SQLUSMALLINT col,
		SQLLEN *indicator)
{
	SQLRETURN ret;

	if(s != NULL)
	{
		*indicator = SQL_NTS;
		ret = SQLBindParameter(stmt,
				col, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
				32, 0, s, strlen(s), indicator);
	}
	else
	{
		*indicator = SQL_NULL_DATA;
		ret = SQLBindParameter(stmt,
				col, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
				0, 0, s, 0, indicator);
	}
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	return APR_SUCCESS;
}

apr_status_t odbc_get_int(int *val, SQLHSTMT stmt,
		SQLUSMALLINT col, SQLLEN *indicator)
{
	SQLRETURN ret;

	*val = 0;

	ret = SQLGetData(stmt, col, SQL_C_SSHORT, val, sizeof(int), indicator);
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	return APR_SUCCESS;
}

apr_status_t odbc_set_int(int *val, SQLHSTMT stmt,
		SQLUSMALLINT col, SQLLEN *indicator)
{
	SQLRETURN ret;

	*indicator = 0;
	ret = SQLBindParameter(stmt,
			col, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, val, sizeof(*val), indicator);
	if(!SQL_SUCCEEDED(ret))
			return APR_EGENERAL;
	return APR_SUCCESS;
}

apr_status_t odbc_get_uint64(uint64_t *v, SQLHSTMT stmt,
		SQLUSMALLINT col, SQLLEN *indicator)
{
	SQLRETURN ret;
	SQLLEN len;
	SQLCHAR buf[33];

	*v = 0;

	ret = SQLGetData(stmt, col, SQL_C_UBIGINT,
			v, sizeof(uint64_t), &len);
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	if (len == SQL_NULL_DATA)
	{
		return APR_SUCCESS;
	}

	/* *v = strtoumax(buf, NULL, 10); */

	return APR_SUCCESS;
}

apr_status_t odbc_set_uint64(uint64_t *v, SQLHSTMT stmt, SQLUSMALLINT col,
		SQLLEN *indicator)
{
	SQLRETURN ret;
	SQLCHAR buf[33];

	if(v != NULL)
	{
		sprintf(buf, "%ju", *v);
		*indicator = SQL_NTS;
		ret = SQLBindParameter(stmt,
				col, SQL_PARAM_INPUT, SQL_C_UBIGINT, SQL_BIGINT,
				0, 0, v, 0, indicator);
	}
	else
	{
		buf[0] = 0;
		*indicator = SQL_NULL_DATA;
		ret = SQLBindParameter(stmt,
				col, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
				0, 0, buf, 0, indicator);
	}
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	return APR_SUCCESS;
}

// convert SQL timestamp to time_t
time_t odbc_sqlts2time(SQL_TIMESTAMP_STRUCT ts)
{
	time_t ret;
	struct tm t;
	t.tm_sec=ts.second;
	t.tm_min=ts.minute;
	t.tm_hour=ts.hour;
	t.tm_mday=ts.day;
	t.tm_mon=ts.month-1;
	t.tm_year=ts.year-1900;
	t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
	ret = timegm(&t);
#else
	ret = mktime(&t) - timezone;
#endif
	return (ret);
}

/* convert time_t to SQL string */
void odbc_time2sqlts(time_t t, char *ret)
{
#ifdef HAVE_GMTIME_R
    struct tm res;
    struct tm* ptime = gmtime_r(&t, &res);
#else
    struct tm* ptime = gmtime(&t);
#endif
    /* strftime(ret, 32, "{ts '%Y-%m-%d %H:%M:%S'}", ptime); */
    strftime(ret, 32, "%Y-%m-%d %H:%M:%S", ptime);
}

apr_status_t odbc_get_datetime(time_t *val, SQLHSTMT stmt,
		SQLUSMALLINT col, SQLLEN *indicator)
{
	SQLRETURN ret;
	SQL_TIMESTAMP_STRUCT _ts;

	*val = 0;

	ret = SQLGetData(stmt, col, SQL_C_TIMESTAMP, &_ts, sizeof(_ts), indicator);
	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	if (*indicator == SQL_NULL_DATA)
		return APR_SUCCESS;

	/* Convert the SQL data to time_t */
	*val = odbc_sqlts2time(_ts);

	return APR_SUCCESS;
}

apr_status_t odbc_set_datetime(time_t *val, SQLHSTMT stmt,
		SQLUSMALLINT col, SQLLEN *indicator, apr_pool_t *pool)
{
	SQLRETURN ret;
	SQLCHAR *_datestr = NULL;
	SQLLEN _slen = 0;

	if(*val != 0)
	{
		if((_datestr = apr_pcalloc(pool, strlen("yyyy-mm-dd hh:mm:ss") + 1))
			== NULL)
			return APR_EGENERAL;

		odbc_time2sqlts(*val, _datestr);
		*indicator = SQL_NTS;
		_slen = strlen(_datestr);
	}
	else
	{
		*indicator = SQL_NULL_DATA;
	}

	ret = SQLBindParameter(stmt,
			col, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_TYPE_TIMESTAMP,
			strlen("yyyy-mm-dd hh:mm:ss"), 0, _datestr, _slen,
			indicator);

	if(!SQL_SUCCEEDED(ret))
		return APR_EGENERAL;

	return APR_SUCCESS;
}

void odbc_cleanup(odbc_connection_t *c)
{
	SQLDisconnect(c->dbc);
	SQLFreeHandle(SQL_HANDLE_DBC, c->dbc);
	SQLFreeHandle(SQL_HANDLE_ENV, c->env);
	apr_pool_destroy(c->pool);
}

void odbc_error_cleanup(char *function_name, odbc_connection_t *c)
{
	extract_error(function_name, c->dbc, SQL_HANDLE_DBC, c->pool);
	odbc_cleanup(c);
}

apr_status_t odbc_build_connection(odbc_connection_t **c, apr_pool_t *pool)
{
	SQLRETURN ret; /* ODBC API return status */
	SQLCHAR qry_select[]=DB_SELECT, qry_update[]=DB_UPDATE;
	odbc_connection_t *_c;
	apr_pool_t *_pool;

	SQLCHAR outstr[1024];
	SQLSMALLINT outstrlen;

	char *_dsn = DB_DSN;

	*c = NULL;

	if(apr_pool_create(&_pool, pool) != APR_SUCCESS)
		return APR_EGENERAL;

	if((_c = apr_pcalloc(_pool, sizeof(odbc_connection_t))) == NULL)
		return APR_EGENERAL;

	_c->pool = _pool;

	/* Allocate an environment handle */
	ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &(_c->env));
	if(!SQL_SUCCEEDED(ret))
	{
		fprintf(stderr, "Failed query\n");
		extract_error("SQLAllocHandle", NULL, SQL_NULL_HANDLE, _pool);
		return APR_EGENERAL;
	}

	/* We want ODBC 3 support */
	ret = SQLSetEnvAttr(_c->env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
	if(!SQL_SUCCEEDED(ret))
	{
		fprintf(stderr, "Failed query\n");
		extract_error("SQLSetEnvAttr", _c->env, SQL_HANDLE_ENV, _pool);
		SQLFreeHandle(SQL_HANDLE_ENV, _c->env);
		return APR_EGENERAL;
	}

	/* Allocate a connection handle */
	ret = SQLAllocHandle(SQL_HANDLE_DBC, _c->env, &(_c->dbc));
	if(!SQL_SUCCEEDED(ret))
	{
		fprintf(stderr, "Failed query\n");
		extract_error("SQLAllocHandle", _c->env, SQL_HANDLE_ENV, _pool);
		SQLFreeHandle(SQL_HANDLE_ENV, _c->env);
		return APR_EGENERAL;
	}

	/* Connect to the DSN mydsn */
	ret = SQLDriverConnect(_c->dbc, NULL, _dsn, SQL_NTS,
			outstr, sizeof(outstr), &outstrlen,
			SQL_DRIVER_COMPLETE);
	if(!SQL_SUCCEEDED(ret))
	{
		fprintf(stderr, "Failed query\n");
		extract_error("SQLDriverConnect", _c->dbc, SQL_HANDLE_DBC, _pool);
		SQLFreeHandle(SQL_HANDLE_DBC, _c->dbc);
		SQLFreeHandle(SQL_HANDLE_ENV, _c->env);
		return APR_EGENERAL;
	}

	ret = SQLAllocStmt(_c->dbc, &(_c->query_stmt));
	if(!SQL_SUCCEEDED(ret))
	{
		odbc_error_cleanup("SQLAllocStmt", _c);
		return APR_EGENERAL;
	}

	ret = SQLPrepare(_c->query_stmt, qry_select, SQL_NTS);
	if(!SQL_SUCCEEDED(ret))
	{
		odbc_error_cleanup("SQLPrepare", _c);
		return APR_EGENERAL;
	}

	ret = SQLAllocStmt(_c->dbc, &(_c->update_stmt));
	if(!SQL_SUCCEEDED(ret))
	{
		odbc_error_cleanup("SQLAllocStmt", _c);
		return APR_EGENERAL;
	}

	ret = SQLPrepare(_c->update_stmt, qry_update, SQL_NTS);
	if(!SQL_SUCCEEDED(ret))
	{
		odbc_error_cleanup("SQLPrepare", _c);
		return APR_EGENERAL;
	}

	*c = _c;

	return APR_SUCCESS;
}

static void user_fetch(dynalogin_user_data_t **ud, const dynalogin_userid_t userid,
		apr_pool_t *pool)
{
	dynalogin_user_data_t *_ud = NULL;
	odbc_connection_t *c;
	SQLRETURN ret; /* ODBC API return status */
	SQLLEN indicator;

	char *_dsn = DB_DSN;

	*ud = NULL;

	if(odbc_build_connection(&c, pool) != APR_SUCCESS)
		return;

	/* bind a parameter with SQLBindParam */
	if(odbc_set_string(userid, c->query_stmt, 1, &indicator) != APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(!SQL_SUCCEEDED(ret = SQLExecute(c->query_stmt)))
	{
		/* FIXME: handle SQL_NO_DATA */
		odbc_error_cleanup("SQLExecute", c);
		return;
	}

	if(SQL_SUCCEEDED(ret = SQLFetch(c->query_stmt))) {
		if((_ud = apr_pcalloc(pool, sizeof(dynalogin_user_data_t))) != NULL)
		{
			odbc_get_string(&(_ud->userid), c->query_stmt, 2, pool);
			odbc_get_string(&(_ud->secret), c->query_stmt, 3, pool);
			odbc_get_uint64(&(_ud->counter), c->query_stmt, 4, &indicator);
			odbc_get_int(&(_ud->failure_count), c->query_stmt, 5, &indicator);
			odbc_get_int(&(_ud->locked), c->query_stmt, 6, &indicator);
			odbc_get_datetime(&(_ud->last_success), c->query_stmt, 7, &indicator);
			odbc_get_datetime(&(_ud->last_attempt), c->query_stmt, 8, &indicator);
			odbc_get_string(&(_ud->last_code), c->query_stmt, 9, pool);
			odbc_get_string(&(_ud->password), c->query_stmt, 10, pool);

			fprintf(stderr, "got user %s count %ju\n", _ud->userid, _ud->counter);
		}
		else
		{
			fprintf(stderr, "apr_pcalloc failed\n");
			odbc_cleanup(c);
			return ;
		}
	} else if(ret == SQL_NO_DATA) {
		fprintf(stderr, "no row found\n");
		odbc_cleanup(c);
		return;
	} else {
		odbc_error_cleanup("SQLFetch", c);
		return;
	}

	odbc_cleanup(c);

	*ud = _ud;

	fprintf(stderr, "user = %s, count = %ju\n", userid, _ud->counter);
	return;
}

static void user_update(dynalogin_user_data_t *ud, apr_pool_t *pool)
{
	odbc_connection_t *c;
	SQLRETURN ret; /* ODBC API return status */
	SQLLEN indicator[8];

	apr_pool_t *_pool;

	if(apr_pool_create(&_pool, pool) != APR_SUCCESS)
		return;

	char *_dsn = DB_DSN;

	if(odbc_build_connection(&c, pool) != APR_SUCCESS)
		return;

	/* bind a parameter with SQLBindParam */
	if(odbc_set_uint64(&(ud->counter), c->update_stmt, 1, &indicator[1]) !=
			APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_int(&(ud->failure_count), c->update_stmt, 2, &indicator[2]) !=
		APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_int(&(ud->locked), c->update_stmt, 3, &indicator[3]) !=
			APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_datetime(&(ud->last_success), c->update_stmt, 4, &indicator[4],
			_pool)
			!= APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_datetime(&(ud->last_attempt), c->update_stmt, 5, &indicator[5],
			_pool)
			!= APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_string(ud->last_code, c->update_stmt, 6, &indicator[6]) !=
			APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(odbc_set_string(ud->userid, c->update_stmt, 7, &indicator[7]) !=
			APR_SUCCESS)
	{
		odbc_error_cleanup("SQLBindParameter", c);
		return;
	}

	if(!SQL_SUCCEEDED(ret = SQLExecute(c->update_stmt)))
	{
		odbc_error_cleanup("SQLExecute", c);
		return ;
	}

	odbc_cleanup(c);

	apr_pool_destroy(_pool);
	fprintf(stderr, "UPDATED user = %s, count = %ju\n", ud->userid, ud->counter);
	return;
}

dynalogin_datastore_module_t odbc_ds_module =
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
