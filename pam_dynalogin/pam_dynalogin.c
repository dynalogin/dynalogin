/*
 * pam_dynalogin.c - a PAM module for dynalogin one-time passwords
 * Copyright (C) 2009-2013 Simon Josefsson
 * Copyright (C) 2013 Daniel Pocock <daniel@pocock.com.au>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "dynaloginclient.h"

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#define D(x) do {							\
		printf ("[%s:%s(%d)] ", __FILE__, __FUNCTION__, __LINE__);		\
		printf x;								\
		printf ("\n");							\
} while (0)
#define DBG(x) if (cfg.debug) { D(x); }

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#define MIN_OTP_LEN 6
#define MAX_OTP_LEN 8

const char *schemes[] = { "HOTP", "TOTP", NULL };

struct cfg
{
	int debug;
	int alwaysok;
	int try_first_pass;
	int use_first_pass;
	char *server;
	unsigned port;
	char *ca_file;
	const char *scheme;
};

static const char *
get_scheme_if_valid(const char *_scheme)
{
	const char *p;
	for(p = schemes[0]; p != NULL; p++)
		if(strcasecmp(p, _scheme) == 0)
			return p;
	return NULL;
}

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
	int i;

	cfg->debug = 0;
	cfg->alwaysok = 0;
	cfg->try_first_pass = 0;
	cfg->use_first_pass = 0;
	cfg->server = NULL;
	cfg->port = -1;
	cfg->ca_file = NULL;
	cfg->scheme = schemes[0];

	for (i = 0; i < argc; i++)
	{
		if (strcmp (argv[i], "debug") == 0)
			cfg->debug = 1;
		if (strcmp (argv[i], "alwaysok") == 0)
			cfg->alwaysok = 1;
		if (strcmp (argv[i], "try_first_pass") == 0)
			cfg->try_first_pass = 1;
		if (strcmp (argv[i], "use_first_pass") == 0)
			cfg->use_first_pass = 1;
		if (strncmp (argv[i], "server=", 7) == 0)
			cfg->server = (char *) argv[i] + 7;
		if (strncmp (argv[i], "port=", 5) == 0)
			cfg->port = atoi (argv[i] + 5);
		if (strncmp (argv[i], "ca_file=", 8) == 0)
			cfg->ca_file = (char *) argv[i] + 8;
		if (strncmp (argv[i], "scheme=", 7) == 0)
			cfg->scheme = get_scheme_if_valid((char *) argv[i] + 7);
	}

	if (cfg->server == NULL)
	{
		D (("missing server name"));
		cfg->port = -1;
	}

	if (cfg->port < 1 || cfg->port > 65535)
	{
		D (("invalid or missing port number"));
		cfg->port = -1;
	}

	if (cfg->debug)
	{
		D (("called."));
		D (("flags %d argc %d", flags, argc));
		for (i = 0; i < argc; i++)
			D (("argv[%d]=%s", i, argv[i]));
		D (("debug=%d", cfg->debug));
		D (("alwaysok=%d", cfg->alwaysok));
		D (("try_first_pass=%d", cfg->try_first_pass));
		D (("use_first_pass=%d", cfg->use_first_pass));
		D (("server=%s", cfg->server ? cfg->server : "(null)"));
		D (("port=%d", cfg->port));
	}
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		int flags, int argc, const char **argv)
{
	int retval, rc;
	dynalogin_client_t *session;
	const char *user = NULL;
	const char *password = NULL;
	char otp[MAX_OTP_LEN + 1];
	int password_len = 0;
	struct pam_conv *conv;
	struct pam_message *pmsg[1], msg[1];
	struct pam_response *resp;
	int nargs = 1;
	struct cfg cfg;
	char *query_prompt = NULL;
	char *onlypasswd = strdup ("");	/* empty passwords never match */

	parse_cfg (flags, argc, argv, &cfg);

	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
	{
		DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
		goto done;
	}
	DBG (("get user returned: %s", user));

	if (cfg.try_first_pass || cfg.use_first_pass)
	{
		retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
		if (retval != PAM_SUCCESS)
		{
			DBG (("get password returned error: %s",
					pam_strerror (pamh, retval)));
			goto done;
		}
		DBG (("get password returned: %s", password));
	}

	if (cfg.use_first_pass && password == NULL)
	{
		DBG (("use_first_pass set and no password, giving up"));
		retval = PAM_AUTH_ERR;
		goto done;
	}

	session = dynalogin_session_start(cfg.server, cfg.port, cfg.ca_file);
	if (session == NULL)
	{
		DBG (("dynalogin_session_start() failed"));
		retval = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}

	if (password == NULL)
	{
		retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
		if (retval != PAM_SUCCESS)
		{
			DBG (("get conv returned error: %s", pam_strerror (pamh, retval)));
			goto done;
		}

		pmsg[0] = &msg[0];
		{
			const char *query_template = "One-time password (OATH) for `%s': ";
			size_t len = strlen (query_template) + strlen (user);
			size_t wrote;

			query_prompt = malloc (len);
			if (!query_prompt)
			{
				retval = PAM_BUF_ERR;
				goto done;
			}

			wrote = snprintf (query_prompt, len, query_template, user);
			if (wrote < 0 || wrote >= len)
			{
				retval = PAM_BUF_ERR;
				goto done;
			}

			msg[0].msg = query_prompt;
		}
		msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
		resp = NULL;

		retval = conv->conv (nargs, (const struct pam_message **) pmsg,
				&resp, conv->appdata_ptr);

		free (query_prompt);
		query_prompt = NULL;

		if (retval != PAM_SUCCESS)
		{
			DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
			goto done;
		}

		DBG (("conv returned: %s", resp->resp));

		password = resp->resp;
	}

	if (password)
		password_len = strlen (password);
	else
	{
		DBG (("Could not read password"));
		retval = PAM_AUTH_ERR;
		goto done;
	}

	if (password_len < MIN_OTP_LEN)
	{
		DBG (("OTP too short: %s", password));
		retval = PAM_AUTH_ERR;
		goto done;
	}
	else if (password_len > MAX_OTP_LEN)
	{
		DBG (("OTP too long: %s", password));
		retval = PAM_AUTH_ERR;
		goto done;
	}
	else
	{
		strcpy (otp, password);
		password = NULL;
	}

	DBG (("OTP: %s", otp ? otp : "(null)"));

	{
		time_t last_otp;

		rc = dynalogin_session_authenticate(
				session, user, cfg.scheme, otp);
		DBG (("authenticate rc %d", rc));
	}

	if (rc != 0)
	{
		DBG (("One-time password not authorized to login as user '%s'", user));
		retval = PAM_AUTH_ERR;
		goto done;
	}

	retval = PAM_SUCCESS;

	done:
	dynalogin_session_stop(session);
	free (query_prompt);
	free (onlypasswd);
	if (cfg.alwaysok && retval != PAM_SUCCESS)
	{
		DBG (("alwaysok needed (otherwise return with %d)", retval));
		retval = PAM_SUCCESS;
	}
	DBG (("done. [%s]", pam_strerror (pamh, retval)));

	return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_dynalogin_modstruct = {
		"pam_dynalogin",
		pam_sm_authenticate,
		pam_sm_setcred,
		NULL,
		NULL,
		NULL,
		NULL
};

#endif
