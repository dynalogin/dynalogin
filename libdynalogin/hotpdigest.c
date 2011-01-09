/*
 * hotpdigest.c - HOTP with HTTP-style digest
 */

#include <apr_pools.h>
#include <apr_strings.h>

#include <config.h>

#include "hotp.h"

#include <stdio.h>		/* For snprintf, getline. */
#include <string.h>		/* For strverscmp. */

#include "gc.h"

/**
 * make_hex_string:
 * @in: bytes
 * @out: string (pre-allocated, with space for trailing 0)
 * @len: sizeof(in)
 **/
void
make_hex_string(const char *in, char *out, size_t len)
{
  char *hex_digit = "0123456789abcdef";
  char *p = out;
  size_t c = 0;
  while ( c < len ) {
    *(p++) = hex_digit[(in[c] >> 4) & 0xf];
    *(p++) = hex_digit[in[c] & 0xf];
    c++;
  }
  *p = 0;
}

/**
 * hotp_validate_otp_digest:
 * @secret: the shared secret string
 * @secret_length: length of @secret
 * @start_moving_factor: start counter in OTP stream
 * @window: how many OTPs from start counter to test
 * @digits: the number of digits to use
 * @response: the HTTP Digest response to validate.
 * @username: the username
 * @realm: the realm
 * @digest_suffix: the nonce and a2 (nonce:ha2)
 *
 * Validate an OTP according to OATH HOTP algorithm per RFC 4226
 * and HTTP Digest RFC 2069 or RFC 2617
 *
 * Currently only OTP lengths of 6, 7 or 8 digits are supported.  This
 * restrictions may be lifted in future versions, although some
 * limitations are inherent in the protocol.
 *
 * Returns: Returns position in OTP window (zero is first position),
 *   or %HOTP_INVALID_OTP if no OTP was found in OTP window, or an
 *   error code.
 **/
int
hotp_validate_otp_digest (const char *secret,
		   size_t secret_length,
		   uint64_t start_moving_factor,
		   size_t window,
		   int digits, const char *response,
		   const char *username, const char *realm,
		   const char *digest_suffix,
		   apr_pool_t *pool)
{
  unsigned iter = 0;
  char tmp_otp[10];
  int rc;
  char *a1;  /* username:realm:password */
  char ha1_raw[GC_MD5_DIGEST_SIZE];  /* H(a1) */
  char ha1_hex[(GC_MD5_DIGEST_SIZE * 2) + 1];
  char *response_arg;   /* H(a1):digest_suffix */
  char _response_raw[GC_MD5_DIGEST_SIZE];
  char _response[(GC_MD5_DIGEST_SIZE * 2) + 1]; /* our calculation of the response */

  apr_pool_t *_pool;

  if(apr_pool_create(&_pool, pool) != APR_SUCCESS)
    {
      return HOTP_CRYPTO_ERROR;
    }

  do
    {
      rc = hotp_generate_otp (secret,
			      secret_length,
			      start_moving_factor + iter,
			      digits,
			      false, HOTP_DYNAMIC_TRUNCATION, tmp_otp);
      if (rc != HOTP_OK)
        {
          apr_pool_destroy(_pool);
	  return rc;
        }

      /* Assemble A1 */
      if((a1 = apr_pstrcat(_pool, 
             username, ":", realm, ":", tmp_otp, NULL)) == NULL)
        {
          apr_pool_destroy(_pool);
          return HOTP_CRYPTO_ERROR;
        }

      /* Calculate H(A1) */
      if(gc_md5(a1, strlen(a1), ha1_raw) != 0)
        {
          apr_pool_destroy(_pool);
          return HOTP_CRYPTO_ERROR;
        }
      make_hex_string(ha1_raw, ha1_hex, GC_MD5_DIGEST_SIZE);

      /* Assemble argument for calculating response */
      if((response_arg = apr_pstrcat(_pool,
            ha1_hex, ":", digest_suffix, NULL)) == NULL)
        {
          apr_pool_destroy(_pool);
          return HOTP_CRYPTO_ERROR;
        }

      /* Calculate response */
      if(gc_md5(response_arg, strlen(response_arg), _response_raw) != 0)
        {
          apr_pool_destroy(_pool);
          return HOTP_CRYPTO_ERROR;
        }
      make_hex_string(_response_raw, _response, GC_MD5_DIGEST_SIZE);

      fprintf(stderr, "a1 = %s ha1 = %s response = %s\n", a1, ha1_hex, _response);

      if (strcmp (response, _response) == 0) {
        apr_pool_destroy(_pool);
	return iter;
      }
    }
  while (window - iter++ > 0);

  apr_pool_destroy(_pool);
  return HOTP_INVALID_OTP;
}

