/*
 * dynalogind.c
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>

#include <apr_file_io.h>
#include <apr_network_io.h>
#include <apr_pools.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>

#include <gnutls/gnutls.h>

#include "dynalogin.h"

#define ERRBUFLEN 1024

#define DEFAULT_CONFIG_FILENAME "dynalogind.conf"
#define DIR_SEP '/'

#define DEFAULT_BIND_ADDR "0.0.0.0"
#define DEFAULT_BIND_PORT 9050

#define DYNALOGIND_PARAM_DETACH "dynalogind.detach"
#define DYNALOGIND_PARAM_TLS_CERT "dynalogind.tls_cert"
#define DYNALOGIND_PARAM_TLS_KEY "dynalogind.tls_key"
#define DYNALOGIND_PARAM_BIND_ADDR "dynalogind.bind_addr"
#define DYNALOGIND_PARAM_BIND_PORT "dynalogind.bind_port"

#define GET_INT_PARAM(r, m, s) \
        if(apr_hash_get(m, s, APR_HASH_KEY_STRING) == NULL) \
                { syslog(LOG_ERR, "missing parameter %s", s); exit(-1); } \
	r = atoi(apr_hash_get(m, s, APR_HASH_KEY_STRING));
#define GET_INT_PARAM_DEF(r, m, s, d) \
	if(apr_hash_get(m, s, APR_HASH_KEY_STRING) == NULL) \
		r = d; \
	else \
		r = atoi(apr_hash_get(m, s, APR_HASH_KEY_STRING));
#define GET_STRING_PARAM_DEF(r, m, s, d) \
	if(apr_hash_get(m, s, APR_HASH_KEY_STRING) == NULL) \
                r = d; \
        else \
		r = apr_hash_get(m, s, APR_HASH_KEY_STRING);

gnutls_certificate_credentials_t x509_cred;
gnutls_priority_t priority_cache;
char *tls_cert = NULL;
char *tls_key = NULL;
static gnutls_dh_params_t dh_params;

typedef struct socket_thread_data_t {
	apr_pool_t *pool;
	apr_socket_t *socket;
	gnutls_session_t *tls_session;
	dynalogin_session_t *dynalogin_session;
} socket_thread_data_t;

/* This is not part of the public API of APR, but
 * we have it here because GNUTLS needs the
 * underlying socket descriptor.
 */
typedef struct apr_socket_t {
    apr_pool_t *pool;
    int socketdes;
} apr_socket_t;

apr_status_t read_line(apr_pool_t *pool, socket_thread_data_t *td,
		char **buf, apr_size_t bufsize)
{
	char errbuf[ERRBUFLEN + 1];
	apr_status_t res;
	char *_buf;
	apr_size_t readsize = bufsize, i;
	int ret;

	if((*buf = apr_pcalloc(pool, bufsize))==NULL)
	{
		syslog(LOG_ERR, "read_line: apr_pcalloc failed");
		apr_pool_destroy(pool);
		return;
	}
	_buf = *buf;

	if(td->tls_session == NULL)
	{
		res = apr_socket_recv(td->socket, _buf, &readsize);

		if(res == APR_SUCCESS || res == APR_EOF)
		{
			_buf[readsize] = 0;
			for(i = 0; i < readsize; i++)
				if(_buf[i] == '\r' || _buf[i] == '\n')
					_buf[i] = 0;
		}
		else
			syslog(LOG_ERR, "unexpected result while reading socket: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
	}
	else
	{
		ret = gnutls_record_recv (*(td->tls_session), _buf, bufsize);
		if (ret == 0)
		{
			// Connection has been closed by peer
			_buf[0] = 0;
			res = APR_EOF;
		}
		else if (ret < 0)
		{
			syslog(LOG_ERR, "received corrupted "
					"data(GNUTLS error code = %d). Closing the connection", ret);
			res = APR_EGENERAL;
		}
		else if (ret > 0)
		{
			_buf[ret] = 0;
			for(i = 0; i < ret; i++)
				if(_buf[i] == '\r' || _buf[i] == '\n')
					_buf[i] = 0;
			res = APR_SUCCESS;
		}
	}

	return res;
}

apr_status_t send_answer(socket_thread_data_t *td, const char *answer)
{
	apr_size_t msglen;
	apr_size_t sent;
	apr_size_t total_sent = 0;
	apr_status_t res;

	msglen = strlen(answer);
	if(td->tls_session == NULL)
	{
		while(total_sent < msglen)
		{
			sent = msglen;
			res = apr_socket_send(td->socket, answer + total_sent, &sent);
			if(res != APR_SUCCESS)
				return res;
			total_sent += sent;
		}
	}
	else
	{
		if(gnutls_record_send (*(td->tls_session), answer, msglen) < 0)
		{
			syslog(LOG_ERR, "gnutls_record_send error");
			return APR_EGENERAL;
		}
	}
	return APR_SUCCESS;
}

apr_status_t send_result(socket_thread_data_t *td, int code)
{
	switch(code)
	{
	case 220:
		return send_answer(td, "220 Service ready\n");
		break;
        case 221:
		return send_answer(td, "221 Closing connection\n");
                break;
	case 250:
		return send_answer(td, "250 OK\n");
		break;
	case 401:
		return send_answer(td, "401 Unauthorized\n");
		break;
	case 500:
		return send_answer(td, "500 Error\n");
                break;
	default:
		return APR_EINVAL;
	}
}

static int
generate_dh_params (void)
{
  int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW);

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, bits);

  return 0;
}

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  gnutls_priority_set (session, priority_cache);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  /* We don't request any certificate from the client.
   * If we did we would need to verify it.
   */
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);

  return session;
}

int count_pointers(char **argv)
{
	int c = 0;
	char **_argv = argv;
	while(*_argv != NULL)
	{
		_argv++;
		c++;
	}
	return c;
}

void socket_thread_handle(socket_thread_data_t *td)
{
	char *buf;
	char errbuf[ERRBUFLEN + 1];
	apr_size_t bufsize = 1024;
	apr_size_t readsize = bufsize;
	char **argv;
	apr_status_t res;
	dynalogin_result_t dynalogin_res;

	apr_pool_t *query_pool;

	int ntokens;

	char *selected_mode;
	dynalogin_userid_t userid;
	dynalogin_scheme_t scheme;
	dynalogin_code_t code;

	char *digest_realm;
	char *digest_response;
	char *digest_suffix;

	if((res=apr_pool_create(&query_pool, td->pool))!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to create query pool: %s",
						apr_strerror(res, errbuf, ERRBUFLEN));
		return;
	}

	if(send_result(td, 220)!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to send greeting");
		return;
	}

	readsize = bufsize;
	res = read_line(query_pool, td, &buf, bufsize);
	while(res == APR_SUCCESS || res == APR_EOF)
	{
		if((res=apr_tokenize_to_argv(buf, &argv, query_pool))
				!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed to tokenize query: %s",
							apr_strerror(res, errbuf, ERRBUFLEN));
			return;
		}
		ntokens = count_pointers(argv);

		/* Examine the command sent by the client */
		if(ntokens < 1)
		{
			syslog(LOG_WARNING, "insufficient tokens in query");
                        res = send_result(td, 500);
		}
		else if(strcasecmp(argv[0], "QUIT")==0)
		{
			send_result(td, 221);
			return;
		}
                else if(strcasecmp(argv[0], "UDATA")==0)
		{
			/* User sending user ID and response value */
			selected_mode=argv[1];
			if(ntokens < 1)
			{
                                /* Command too short */
                                syslog(LOG_WARNING, "insufficient tokens in query");
                                res = send_result(td, 500);
			}
			else if(strcasecmp(selected_mode, "HOTP") == 0 ||
					strcasecmp(selected_mode, "TOTP") == 0)
			{
				userid=argv[2];
				scheme = selected_mode[0] == 'H' ? HOTP : TOTP;
				code=argv[3];
				if(ntokens < 4)
				{
					/* Command too short */
					syslog(LOG_WARNING, "insufficient tokens in query");
					res = send_result(td, 500);
				}
				else
				{
					syslog(LOG_DEBUG, "attempting DYNALOGIN auth for user=%s", userid);
					dynalogin_res = dynalogin_authenticate(td->dynalogin_session,
						userid, scheme, code);

					switch(dynalogin_res)
					{
					case DYNALOGIN_SUCCESS:
						syslog(LOG_DEBUG, "DYNALOGIN success for user=%s", userid);
						res = send_result(td, 250);
						break;
					case DYNALOGIN_DENY:
						/* User unknown or bad password */
						syslog(LOG_DEBUG, "DYNALOGIN denied for user=%s", userid);
						res = send_result(td, 401);
						break;
					case DYNALOGIN_ERROR:
						/* Error connecting to DB, etc */
						syslog(LOG_DEBUG, "DYNALOGIN error for user=%s", userid);
						res = send_result(td, 500);
						break;
					default:
						syslog(LOG_DEBUG, "DYNALOGIN unexpected result for user=%s", userid);
						res = send_result(td, 500);
					}
				}
			} else if (strcasecmp(selected_mode, "HOTP-DIGEST") == 0 ||
					strcasecmp(selected_mode, "TOTP-DIGEST") == 0)
			{
				/* HOTP Digest mode */
				userid = argv[2];
				scheme = selected_mode[0] == 'H' ? HOTP : TOTP;
				digest_realm = argv[3];
				digest_response = argv[4];
				digest_suffix = argv[5];
				if(ntokens < 6)
				{
					/* Command too short */
					syslog(LOG_WARNING, "insufficient tokens in query");
					res = send_result(td, 500);
				}
				else
				{
					syslog(LOG_DEBUG, "attempting DYNALOGIN digest auth for user=%s", userid);
					dynalogin_res = dynalogin_authenticate_digest(td->dynalogin_session, 
						userid, scheme, digest_response, digest_realm, digest_suffix);

					switch(dynalogin_res)
					{
					case DYNALOGIN_SUCCESS:
						syslog(LOG_DEBUG, "DYNALOGIN success for user=%s", userid);
						res = send_result(td, 250);
						break;
					case DYNALOGIN_DENY:
						/* User unknown or bad password */
						syslog(LOG_DEBUG, "DYNALOGIN denied for user=%s", userid);
						res = send_result(td, 401);
						break;
					case DYNALOGIN_ERROR:
						/* Error connecting to DB, etc */
						syslog(LOG_DEBUG, "DYNALOGIN error for user=%s", userid);
						res = send_result(td, 500);
						break;
					default:
						syslog(LOG_DEBUG, "DYNALOGIN unexpected result for user=%s", userid);
						res = send_result(td, 500);
					}
				}
			} else {
				syslog(LOG_WARNING, "unsupported mode requested");
                        	res = send_result(td, 500);
			}
		}
		else
		{
			/* Unrecognised command */
			res = send_result(td, 500);
		}
	
		if(res != APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed to send response: %s",
					apr_strerror(res, errbuf, ERRBUFLEN));
			return;
		}

		apr_pool_destroy(query_pool);
		if((res=apr_pool_create(&query_pool, td->pool))!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed to create query pool: %s",
							apr_strerror(res, errbuf, ERRBUFLEN));
			return;
		}
		res = read_line(query_pool, td, &buf, bufsize);
	}
	syslog(LOG_ERR, "failed to read input from socket: %s",
					apr_strerror(res, errbuf, ERRBUFLEN));
}

void socket_thread_main(apr_thread_t *self, void *data)
{
	int ret = 0;
	socket_thread_data_t *thread_data = (socket_thread_data_t*)data;
	gnutls_session_t session;

	if(tls_cert != NULL)
	{
		if((thread_data->tls_session=apr_pcalloc(
				thread_data->pool, sizeof(gnutls_session_t)))!=NULL)
		{
			session = initialize_tls_session ();
			gnutls_transport_set_ptr (session,
					(gnutls_transport_ptr_t) (thread_data->socket->socketdes));
			do
			{
				ret = gnutls_handshake (session);
			}
			while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

			if (ret < 0)
			{
				syslog(LOG_ERR, "handshake has failed (%s)\n\n", gnutls_strerror (ret));
			}
			*(thread_data->tls_session) = session;
		}
		else
		{
			syslog(LOG_ERR, "memory allocation failure");
			ret = -1;
		}
	}

	if(ret >= 0)
	{
		socket_thread_handle(thread_data);
		if(thread_data->tls_session != NULL)
			gnutls_bye(session, GNUTLS_SHUT_WR);
	}

	apr_socket_close(thread_data->socket);
	if(thread_data->tls_session != NULL)
		gnutls_deinit (session);
	apr_pool_destroy(thread_data->pool);
	syslog(LOG_INFO, "client connection closed");
}

apr_status_t handle_new_client(apr_socket_t *socket, apr_pool_t *pool,
		dynalogin_session_t *h)
{
	char buf[ERRBUFLEN + 1];

	apr_status_t res;
	apr_threadattr_t *t_attr;
	apr_thread_t *t;
	apr_pool_t *subpool;
	socket_thread_data_t *thread_data;

	res = apr_pool_create(&subpool, pool);
	if(res != APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to create pool: %s",
				apr_strerror(res, buf, ERRBUFLEN));
		apr_socket_close(socket);
		return res;
	}

	res = apr_threadattr_create(&t_attr, subpool);
	if(res != APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to create threadattr: %s",
				apr_strerror(res, buf, ERRBUFLEN));
		apr_pool_destroy(subpool);
		apr_socket_close(socket);
		return res;
	}

	thread_data = apr_pcalloc(subpool, sizeof(struct socket_thread_data_t));
	if(thread_data == NULL)
	{
		syslog(LOG_ERR, "handle_new_client: apr_pcalloc failed");
		apr_pool_destroy(subpool);
		apr_socket_close(socket);
		return res;
	}

	thread_data->pool = subpool;
	thread_data->socket = socket;
	thread_data->tls_session = NULL;  // to be populated later if using TLS
	thread_data->dynalogin_session = h;

	res = apr_thread_create(&t, t_attr,
			(apr_thread_start_t)socket_thread_main, thread_data, subpool);

	if(res != APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to spawn a thread: %s",
				apr_strerror(res, buf, ERRBUFLEN));
		apr_pool_destroy(subpool);
		apr_socket_close(socket);
	}

	return res;
}

int main(int argc, char *argv[])
{
	char errbuf[ERRBUFLEN + 1];
	apr_pool_t *pool;
	apr_proc_t proc;
	dynalogin_session_t *h;
	apr_status_t res;

	apr_sockaddr_t *sa;
	apr_socket_t *socket, *socket_new;

	char *cfg_filename;
	char *bind_address;
	int bind_port;
	int qlen = 32;
	int cfg_detach = 1;
	int ret;

	int done = 0;

	apr_hash_t *config;

	if(apr_initialize() != APR_SUCCESS)
	{
		fprintf(stderr, "apr_initialize failed\n");
		return 1;
	}

	/* Just return an error if a client closes a socket */
	apr_signal_block(SIGPIPE);

	openlog(argv[0], LOG_PID, LOG_AUTHPRIV);

	if((res = apr_pool_create(&pool, NULL)) != APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to create root pool: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		return 1;
	}

	if(argc == 2)
		cfg_filename = argv[1];
	else
		cfg_filename = apr_psprintf(pool, "%s%c%s",
			SYSCONFDIR, DIR_SEP, DEFAULT_CONFIG_FILENAME);
	if(cfg_filename == NULL)
	{
		syslog(LOG_ERR, "apr_psprintf failed to create filename: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		return 1;
	}
	/* Read config */
	if(dynalogin_read_config_from_file(&config, cfg_filename, pool)
			!= DYNALOGIN_SUCCESS)
	{
		syslog(LOG_ERR, "failed to read config file %s",
				cfg_filename);
		return 1;
	}

	/* Set up DYNALOGIN session (threadsafe?) */
	if(dynalogin_init(&h, pool, config) != DYNALOGIN_SUCCESS)
	{
		syslog(LOG_ERR, "failed to init dynalogin stack");
		return 1;
	}

	/* Daemonize? */
	GET_INT_PARAM(cfg_detach, config, DYNALOGIND_PARAM_DETACH)
	if((res=apr_proc_detach(cfg_detach)) != APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to detach: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		return 1;
	}

	/* Create socket for clients */
	if((res=apr_socket_create(&socket,
			APR_INET, SOCK_STREAM, APR_PROTO_TCP, pool))!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to create listening socket: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		return 1;
	}
	GET_STRING_PARAM_DEF(bind_address, config, DYNALOGIND_PARAM_BIND_ADDR, DEFAULT_BIND_ADDR)
	GET_INT_PARAM_DEF(bind_port, config, DYNALOGIND_PARAM_BIND_PORT, DEFAULT_BIND_PORT)
	if((res=apr_sockaddr_info_get(&sa, bind_address, APR_UNSPEC,
			bind_port, APR_IPV4_ADDR_OK || APR_IPV6_ADDR_OK, pool))!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to resolve bind address: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		apr_socket_close(socket);
		return 1;
	}
	if((res=apr_socket_opt_set(socket, APR_SO_REUSEADDR, 1))!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to set APR_SO_REUSEADDR: %s",
			apr_strerror(res, errbuf, ERRBUFLEN));
		apr_socket_close(socket);
		return 1;
	}
	if((res=apr_socket_bind(socket, sa))!=APR_SUCCESS)
	{
		syslog(LOG_ERR, "failed to bind: %s",
				apr_strerror(res, errbuf, ERRBUFLEN));
		apr_socket_close(socket);
		return 1;
	}

	GET_STRING_PARAM_DEF(tls_cert, config, DYNALOGIND_PARAM_TLS_CERT, NULL)
	GET_STRING_PARAM_DEF(tls_key, config, DYNALOGIND_PARAM_TLS_KEY, NULL)
	if(tls_cert != NULL)
	{
		if(tls_key == NULL)
		{
			syslog(LOG_ERR, "%s specified, but %s not specified", DYNALOGIND_PARAM_TLS_CERT,
					DYNALOGIND_PARAM_TLS_KEY);
			return 1;
		}

		gnutls_global_init ();

		gnutls_certificate_allocate_credentials (&x509_cred);
		/* gnutls_certificate_set_x509_system_trust(xcred); */
		/* gnutls_certificate_set_verify_flags (x509_cred,
		                                       GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5); */
		/* gnutls_certificate_set_x509_trust_file (x509_cred, "/etc/ssl/certs/ca-certificates.txt",
				GNUTLS_X509_FMT_PEM); */

		/* gnutls_certificate_set_x509_crl_file (x509_cred, "/tmp/crl.pem",
				GNUTLS_X509_FMT_PEM); */

		ret = gnutls_certificate_set_x509_key_file (x509_cred, tls_cert, tls_key,
				GNUTLS_X509_FMT_PEM);
		if (ret < 0)
		{
			syslog(LOG_ERR, "No certificate or key were found");
			return 1;
		}

		generate_dh_params ();

		gnutls_priority_init (&priority_cache, "PERFORMANCE:%SERVER_PRECEDENCE", NULL);

		gnutls_certificate_set_dh_params (x509_cred, dh_params);
	}
	else if(tls_key == NULL)
	{
		syslog(LOG_ERR, "%s specified, but %s not specified", DYNALOGIND_PARAM_TLS_KEY,
				DYNALOGIND_PARAM_TLS_CERT);
		return 1;
	}

	/* Main loop */
	while(done != 1)
	{
		if((res=apr_socket_listen(socket, qlen))!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed apr_socket_listen: %s",
					apr_strerror(res, errbuf, ERRBUFLEN));
			apr_socket_close(socket);
			return 1;
		}

		if((res=apr_socket_accept(&socket_new, socket, pool))!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed to accept incoming connection: %s",
					apr_strerror(res, errbuf, ERRBUFLEN));
			apr_socket_close(socket);
			return 1;
		}
		syslog(LOG_INFO, "new incoming connection");
		if((res=handle_new_client(socket_new, pool, h))!=APR_SUCCESS)
		{
			syslog(LOG_ERR, "failed to handle incoming connection: %s",
					apr_strerror(res, errbuf, ERRBUFLEN));
			apr_socket_close(socket);
			return 1;
		}
	}
	apr_socket_close(socket);
	return 0;
}
