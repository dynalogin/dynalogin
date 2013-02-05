

#include <stdio.h>
#include <stdlib.h>

#include "dynaloginclient.h"

int main(int argc, char *argv[])
{
	char *host;
	int port;
	char *user;
	char *scheme;
	char *code;
	dynalogin_client_t *session;
	int ret;

	if(argc < 6)
	{
		fprintf(stderr, "please specify host, port, user, scheme and code");
		return 1;
	}

	host = argv[1];
	port = atoi(argv[2]);
	user = argv[3];
	scheme = argv[4];
	code = argv[5];

	session = dynalogin_session_start(host, port, NULL);

	if(session == NULL)
	{
		fprintf(stderr, "failed to get session");
		return 1;
	}

	ret = dynalogin_session_authenticate(session, user, scheme, code);

	printf("return value from OATH: %d\n", ret);

	dynalogin_session_stop(session);
}

