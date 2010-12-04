/*
 * hotp.c - implementation of the HOTP algorithm
 * Copyright (C) 2009  Simon Josefsson
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#ifndef HOTP_H
# define HOTP_H

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

/**
 * HOTP_VERSION
 *
 * Pre-processor symbol with a string that describe the header file
 * version number.  Used together with hotp_check_version() to verify
 * header file and run-time library consistency.
 */
# define HOTP_VERSION "1.0.1"

/**
 * HOTP_VERSION_MAJOR
 *
 * Pre-processor symbol with a decimal value that describe the major
 * level of the header file version number.  For example, when the
 * header version is 1.2.3 this symbol will be 1.
 */
# define HOTP_VERSION_MAJOR 0

/**
 * HOTP_VERSION_MINOR
 *
 * Pre-processor symbol with a decimal value that describe the minor
 * level of the header file version number.  For example, when the
 * header version is 1.2.3 this symbol will be 2.
 */
# define HOTP_VERSION_MINOR 0

/**
 * HOTP_VERSION_PATCH
 *
 * Pre-processor symbol with a decimal value that describe the patch
 * level of the header file version number.  For example, when the
 * header version is 1.2.3 this symbol will be 3.
 */
# define HOTP_VERSION_PATCH 1

/**
 * HOTP_VERSION_NUMBER
 *
 * Pre-processor symbol with a hexadecimal value describing the
 * header file version number.  For example, when the header version
 * is 1.2.3 this symbol will have the value 0x010203.
 */
# define HOTP_VERSION_NUMBER 0x010001

/**
 * hotp_rc:
 * @HOTP_OK: Successful return
 * @HOTP_CRYPTO_ERROR: Internal error in crypto functions
 * @HOTP_INVALID_DIGITS: Unsupported number of OTP digits
 * @HOTP_PRINTF_ERROR: Error from system printf call
 * @HOTP_INVALID_HEX: Hex string is invalid
 * @HOTP_TOO_SMALL_BUFFER: The output buffer is too small
 * @HOTP_INVALID_OTP: The OTP is not valid
 * @HOTP_REPLAYED_OTP: The OTP has been replayed
 * @HOTP_BAD_PASSWORD: The password does not match
 * @HOTP_INVALID_COUNTER: The counter value is corrupt
 * @HOTP_INVALID_TIMESTAMP: The timestamp is corrupt
 * @HOTP_NO_SUCH_FILE: The supplied filename does not exist
 * @HOTP_UNKNOWN_USER: Cannot find information about user
 * @HOTP_FILE_SEEK_ERROR: System error when seeking in file
 * @HOTP_FILE_CREATE_ERROR: System error when creating file
 * @HOTP_FILE_LOCK_ERROR: System error when locking file
 * @HOTP_FILE_RENAME_ERROR: System error when renaming file
 * @HOTP_FILE_UNLINK_ERROR: System error when removing file
 * @HOTP_TIME_ERROR: System error for time manipulation
 *
 * Return codes for HOTP functions.  All return codes are negative
 * except for the successful code HOTP_OK which are guaranteed to be
 * 0.  Positive values are reserved for non-error return codes.
 *
 * Note that the #hotp_rc enumeration may be extended at a later date
 * to include new return codes.
 */
typedef enum
{
  HOTP_OK = 0,
  HOTP_CRYPTO_ERROR = -1,
  HOTP_INVALID_DIGITS = -2,
  HOTP_PRINTF_ERROR = -3,
  HOTP_INVALID_HEX = -4,
  HOTP_TOO_SMALL_BUFFER = -5,
  HOTP_INVALID_OTP = -6,
  HOTP_REPLAYED_OTP = -7,
  HOTP_BAD_PASSWORD = -8,
  HOTP_INVALID_COUNTER = -9,
  HOTP_INVALID_TIMESTAMP = -10,
  HOTP_NO_SUCH_FILE = -11,
  HOTP_UNKNOWN_USER = -12,
  HOTP_FILE_SEEK_ERROR = -13,
  HOTP_FILE_CREATE_ERROR = -14,
  HOTP_FILE_LOCK_ERROR = -15,
  HOTP_FILE_RENAME_ERROR = -16,
  HOTP_FILE_UNLINK_ERROR = -17,
  HOTP_TIME_ERROR = -18,
} hotp_rc;

#define HOTP_DYNAMIC_TRUNCATION SIZE_MAX

#define HOTP_OTP_LENGTH(digits, checksum) (digits + (checksum ? 1 : 0))

extern HOTPAPI int hotp_init (void);
extern HOTPAPI int hotp_done (void);

extern HOTPAPI const char *hotp_check_version (const char *req_version);

extern HOTPAPI int hotp_hex2bin (char *hexstr, char *binstr, size_t * binlen);

extern HOTPAPI int hotp_generate_otp (const char *secret,
				      size_t secret_length,
				      uint64_t moving_factor,
				      unsigned digits,
				      bool add_checksum,
				      size_t truncation_offset,
				      char *output_otp);


extern HOTPAPI int hotp_validate_otp (const char *secret,
				      size_t secret_length,
				      uint64_t start_moving_factor,
				      size_t window, const char *otp);

extern HOTPAPI int hotp_authenticate_usersfile (const char *usersfile,
						const char *username,
						const char *otp,
						size_t window,
						const char *passwd,
						time_t * last_otp);

#endif /* HOTP_H */
