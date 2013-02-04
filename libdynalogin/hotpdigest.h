/*
 * hotpdigest.h - HOTP with HTTP-style digest
 *
 */

#ifndef HOTPDIGEST_H
# define HOTPDIGEST_H

# ifndef HOTPAPI
#  if defined LIBHOTP_BUILDING && defined HAVE_VISIBILITY && HAVE_VISIBILITY
#   define HOTPAPI __attribute__((__visibility__("default")))
#  elif defined LIBHOTP_BUILDING && defined _MSC_VER && ! defined LIBHOTP_STATIC
#   define HOTPAPI __declspec(dllexport)
#  elif defined _MSC_VER && ! defined LIBHOTP_STATIC
#   define HOTPAPI __declspec(dllimport)
#  else
#   define HOTPAPI
#  endif
# endif

#include <stdbool.h>		/* For bool. */
#include <stdint.h>		/* For uint64_t, SIZE_MAX. */
#include <string.h>		/* For size_t.t */
#include <time.h>		/* For time_t. */

#include "dynalogin-internal.h"

struct oath_digest_callback_pvt_t
{
	apr_pool_t *pool;
	const char *response;
	const char *username;
	const char *realm;
	const char *digest_suffix;
	const char *password;
};

/* oath_validate_strcmp_function for use by
   oath_hotp_validate_callback */
int oath_digest_callback(void *handle, const char *test_otp);

#endif /* HOTPDIGEST_H */
