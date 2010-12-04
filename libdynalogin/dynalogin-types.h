/*
 * dynalogin-types.h
 *
 *  Created on: 23 May 2010
 *      Author: daniel
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

#endif /* DYNALOGINTYPES_H_ */
