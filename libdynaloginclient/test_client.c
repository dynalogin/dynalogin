

#include <stdio.h>
#include <stdlib.h>

#include "dynaloginclient.h"

int main(int argc, char *argv[])
{
	char *host;
	int port;
	char *user;
	char *code;
	dynalogin_client_t *session;
	int ret;

	if(argc < 5)
	{
		fprintf(stderr, "please specify host, port, user and code");
		return 1;
	}

	host = argv[1];
	port = atoi(argv[2]);
	user = argv[3];
	code = argv[4];

	session = dynalogin_session_start(host, port);

	if(session == NULL)
	{
		fprintf(stderr, "failed to get session");
		return 1;
	}

	ret = dynalogin_authenticate_hotp(session, user, code);

	printf("return value from OATH: %d\n", ret);

	dynalogin_session_stop(session);
}

