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


extern HOTPAPI int hotp_validate_otp_digest (const char *secret,
                   			size_t secret_length,
                   			uint64_t start_moving_factor,
                   			size_t window,
                   			int digits, const char *response,
                   			const char *username, const char *realm,
                   			const char *digest_suffix,
                   			apr_pool_t *pool);

#endif /* HOTPDIGEST_H */
