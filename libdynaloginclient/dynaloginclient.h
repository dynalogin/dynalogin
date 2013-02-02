/*
 * dynaloginclient.h
 */

#ifndef DYNALOGINCLIENT_H_
#define DYNALOGINCLIENT_H_

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

typedef struct dynalogin_client_t {
	char *server;
	int port;
	gnutls_session_t tls_session;
	gnutls_certificate_credentials_t xcred;
	int sd;
	char *read_buf;
	char *read_buf_offset;
} dynalogin_client_t;

dynalogin_client_t *dynalogin_session_start(const char *server, int port, const char *ca_file);
void dynalogin_session_stop(dynalogin_client_t *session);

int dynalogin_authenticate_hotp(dynalogin_client_t *session, const char *user, const char *code);

#endif /* DYNALOGINCLIENT_H_ */
