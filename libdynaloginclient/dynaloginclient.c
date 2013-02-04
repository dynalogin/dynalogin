
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "dynaloginclient.h"

#define MAX_BUF 1024

// FIXME - should be configurable
#define CA_FILE "/etc/ssl/certs/ca-certificates.crt"
#define SA struct sockaddr

int
tcp_connect (const char *server, int port);
void tcp_close(int sd);

static int _verify_certificate_callback (gnutls_session_t session);


#define READ_BUF_SIZE 1024

char *read_line(dynalogin_client_t *session)
{
	char *eol = NULL;
	char *text_line;
	ssize_t read_size, count;
	char *new_buf, *read_pos;

	if(session->read_buf != NULL)
	{
		if(*(session->read_buf_offset) != 0)
		{
			// we already have data from the last read
			eol = strchr(session->read_buf_offset, '\n');
			if(eol != NULL)
			{
				*eol = 0;
				if((text_line = strdup(session->read_buf_offset)) == NULL)
				{
					syslog(LOG_ERR, "strdup failed");
					return NULL;
				}
				session->read_buf_offset = eol + 1;
				return text_line;
			}
			else
			{
				if(session->read_buf == session->read_buf_offset)
				{
					// Line too long
					syslog(LOG_ERR, "line too long from dynalogin server, aborting read");
					return NULL;
				}
			}
		}
		else
		{
			free(session->read_buf);
			session->read_buf = NULL;
		}
	}

	read_size = READ_BUF_SIZE;
	if((new_buf = (char *)malloc(READ_BUF_SIZE + 1))==NULL)
	{
		syslog(LOG_ERR, "malloc failure");
		return NULL;
	}
	read_pos = new_buf;
	if(session->read_buf != NULL)
	{
		strcpy(new_buf, session->read_buf_offset);
		free(session->read_buf);
		count = strlen(new_buf);
		read_pos += count;
		read_size -= count;
	}

	count = gnutls_record_recv(session->tls_session, read_pos, read_size);
	session->read_buf = new_buf;
	session->read_buf_offset = new_buf;

	if (count == 0)
	{
		syslog(LOG_WARNING, "Peer has closed the TLS connection");
		return NULL;
	}
	else if (count < 0)
	{
		syslog(LOG_ERR, "error reading from TLS socket: %s", gnutls_strerror (count));
		return NULL;
	}
	else
	{
		read_pos[count] = 0;
	}
	return read_line(session);
}

int write_line(dynalogin_client_t *session, const char *msg)
{
	gnutls_record_send (session->tls_session, msg, strlen (msg));
	//gnutls_record_send (session->tls_session, "\n", 1);
	return 0;  // FIXME - should check sending status code
}

int dynalogin_authenticate_hotp(dynalogin_client_t *session, const char *user, const char *code) {

	char msg[MAX_BUF];
	char *line;
	int ret, response_code;

	if(snprintf(msg, MAX_BUF-1, "UDATA HOTP %s %s\n", user, code) >= MAX_BUF)
	{
		syslog(LOG_ERR, "user or code too long for buffer, auth failed");
		return -1;
	}
	write_line (session, msg);

	line = read_line (session);
	ret = strlen(line);
	if(ret < 3)
	{
		syslog(LOG_ERR, "auth response too short");
		return -1;
	}
	line[3] = 0;
	response_code = atoi(line);
	free(line);
	if(response_code < 200 || response_code > 299) {
		syslog(LOG_ERR, "unexpected response code (%d), auth failed for user %s", response_code, user);
		return -1;
	}

	syslog(LOG_INFO, "user %s validated successfully, code %d", user, response_code);
	return 0;
}

dynalogin_client_t *dynalogin_session_start(const char *server, int port, const char *ca_file)
{
	int ret, ii;
	char buffer[MAX_BUF + 1];
	const char *err;
	char *line;
	dynalogin_client_t *session;
        char *_ca_file = ca_file;

	if((session = (dynalogin_client_t*)malloc(sizeof(dynalogin_client_t)))==NULL)
	{
		syslog(LOG_ERR, "malloc failure");
		return NULL;
	}
	if((session->server = strdup(server))==NULL)
	{
		free(session);
		syslog(LOG_ERR, "malloc failure");
		return NULL;
	}
	session->port = port;
	session->read_buf = NULL;
	session->read_buf_offset = NULL;

	gnutls_global_init ();

	/* X509 stuff */
	gnutls_certificate_allocate_credentials (&(session->xcred));

	/* sets the trusted cas file
	 */
	if(_ca_file == NULL)
		_ca_file = CA_FILE;
	gnutls_certificate_set_x509_trust_file (session->xcred, _ca_file, GNUTLS_X509_FMT_PEM);
	//gnutls_certificate_set_verify_function (session->xcred, _verify_certificate_callback);

	/* If client holds a certificate it can be set using the following:
	 *
     gnutls_certificate_set_x509_key_file (xcred, 
                                           "cert.pem", "key.pem", 
                                           GNUTLS_X509_FMT_PEM); 
	 */

	/* Initialize TLS session
	 */
	gnutls_init (&(session->tls_session), GNUTLS_CLIENT);

	gnutls_session_set_ptr (session->tls_session, (void *) server);

	gnutls_server_name_set (session->tls_session, GNUTLS_NAME_DNS, server,
			strlen(server));

	/* Use default priorities */
	ret = gnutls_priority_set_direct (session->tls_session, "NORMAL", &err);
	if (ret < 0)
	{
		if (ret == GNUTLS_E_INVALID_REQUEST)
		{
			syslog(LOG_ERR, "Syntax error at: %s", err);
		}
		free(session->server);
		free(session);
		return NULL;
	}

	/* put the x509 credentials to the current session
	 */
	gnutls_credentials_set (session->tls_session, GNUTLS_CRD_CERTIFICATE, session->xcred);

	/* connect to the peer
	 */
	if((session->sd = tcp_connect (server, port)) < 0)
	{
		free(session->server);
		free(session);
		return NULL;
	}

	gnutls_transport_set_ptr (session->tls_session, (gnutls_transport_ptr_t) (session->sd));
	// FIXME: This is only available in gnutls 3.1
	//gnutls_handshake_set_timeout (session->tls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	/* Perform the TLS handshake
	 */
	do
	{
		ret = gnutls_handshake (session->tls_session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0)
	{
		syslog(LOG_ERR, "Handshake failed");
		gnutls_perror (ret);
		free(session->server);
		free(session);
		return NULL;
	}

	// FIXME - now we must check the greeting, it should finish with code 220
	line = read_line(session);
	while(line != NULL)
	{
		if(strlen(line) < 3)
		{
			syslog(LOG_ERR, "line too short: %s", line);
			free(line);
			line = NULL;
		}
		else if(strncmp(line, "220", 3)==0)
		{
			syslog(LOG_DEBUG, "connected to dynalogin server: %s", line);
			free(line);
			return session;
		}
		if(strlen(line) > 3 && line[3] == '-')
		{
			free(line);
			line = read_line(session);
		}
		else
		{
			free(line);
			line = NULL;
		}
	}
	syslog(LOG_ERR, "Error/no valid greeting from dynalogin server");
	gnutls_perror (ret);
	free(session->server);
	free(session);
	return NULL;
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
// FIXME: from more modern gnutls3.1 examples, should we use it?
static int
_verify_certificate_callback_new (gnutls_session_t session)
{
	unsigned int status;
	int ret, type;
	const char *hostname;
	gnutls_datum_t out;

	/* read hostname */
	hostname = gnutls_session_get_ptr (session);

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	// FIXME: gnutls3.1 version:
	//ret = gnutls_certificate_verify_peers3 (session, hostname, &status);
	ret = gnutls_certificate_verify_peers2 (session, &status);
	if (ret < 0)
	{
		syslog(LOG_ERR, "Error verifying server cert");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	type = gnutls_certificate_type_get (session);

	ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
	if (ret < 0)
	{
		syslog(LOG_ERR, "Error verifying server cert");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_free(out.data);

	if (status != 0) /* Certificate is not trusted */
	{
		syslog(LOG_ERR, "Error verifying server cert");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	/* notify gnutls to continue handshake normally */
	return 0;
}

static int
_verify_certificate_callback (gnutls_session_t session)
{
	unsigned int status;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	int ret;
	gnutls_x509_crt_t cert;
	const char *hostname;

	/* read hostname */
	hostname = gnutls_session_get_ptr (session);

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2 (session, &status);
	if (ret < 0)
	{
		printf ("Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		printf ("The certificate hasn't got a known issuer.\n");

	if (status & GNUTLS_CERT_REVOKED)
		printf ("The certificate has been revoked.\n");

	if (status & GNUTLS_CERT_EXPIRED)
		printf ("The certificate has expired\n");

	if (status & GNUTLS_CERT_NOT_ACTIVATED)
		printf ("The certificate is not yet activated\n");

	if (status & GNUTLS_CERT_INVALID)
	{
		printf ("The certificate is not trusted.\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
		return GNUTLS_E_CERTIFICATE_ERROR;

	if (gnutls_x509_crt_init (&cert) < 0)
	{
		printf ("error in initialization\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
	if (cert_list == NULL)
	{
		printf ("No certificate was found!\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
	{
		printf ("error parsing certificate\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}


	if (!gnutls_x509_crt_check_hostname (cert, hostname))
	{
		printf ("The certificate's owner does not match hostname '%s'\n",
				hostname);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_x509_crt_deinit (cert);

	/* notify gnutls to continue handshake normally */
	return 0;
}

void dynalogin_session_stop(dynalogin_client_t *session) {

	write_line (session, "QUIT\n");

	gnutls_bye (session->tls_session, GNUTLS_SHUT_RDWR);
	tcp_close (session->sd);
	gnutls_deinit (session->tls_session);
	gnutls_certificate_free_credentials (session->xcred);
	free(session->server);
	free(session);
}

int
tcp_connect (const char *server, int port)
{
	int err, sd;
	struct sockaddr_in sa;

	/* connects to server
	 */
	sd = socket (AF_INET, SOCK_STREAM, 0);

	memset (&sa, '\0', sizeof (sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons (port);
	inet_pton (AF_INET, server, &sa.sin_addr);

	err = connect (sd, (SA *) & sa, sizeof (sa));
	if (err < 0)
	{
		syslog(LOG_ERR, "Connect error");
		return -1;
	}

	return sd;
}

/* closes the given socket descriptor.
 */
void
tcp_close (int sd)
{
	shutdown (sd, SHUT_RDWR);	/* no more receptions */
	close (sd);
}
