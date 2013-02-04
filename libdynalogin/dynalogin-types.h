/*
 * dynalogin-types.h
 *
 *      Types exposed in the APIs
 */

#ifndef DYNALOGINTYPES_H_
#define DYNALOGINTYPES_H_

#include <stdint.h>

typedef char * dynalogin_userid_t;
typedef char * dynalogin_secret_t;
typedef uint64_t dynalogin_counter_t;
typedef char * dynalogin_code_t;

typedef enum { DYNALOGIN_SUCCESS,
	DYNALOGIN_DENY,
	DYNALOGIN_ERROR,
} dynalogin_result_t;

typedef enum dynalogin_scheme {
	HOTP = 0,
	TOTP = 1
} dynalogin_scheme_t;

#endif /* DYNALOGINTYPES_H_ */
