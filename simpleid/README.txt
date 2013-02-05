

To enable OATH (HOTP and TOTP) authentication from SimpleID:

1. Copy the various PHP scripts from this directory to your SimpleID
   PHP directory.

2. Amend the configuration script

      dynalogin-filesystem.store.config.php

   to specify the location of the dynalogin PHP code, the desired
   dynalogin server hostname, port number, TLS and default scheme:

      define('DYNALOGIN_PHP_DIR', '/usr/share/dynalogin-client-php');
      define('DYNALOGIN_SERVER_NAME', 'localhost');
      define('DYNALOGIN_SERVER_PORT', 9050);
      define('DYNALOGIN_USE_TLS', true);
      define('DYNALOGIN_DEFAULT_SCHEME, 'HOTP');

3. Create user identity files (or amend existing identity files) with
   particular reference to the dynalogin parameters - see the include
   sample file:

      example-dynalogin.identity.dist

4. In the main SimpleID config.php, change the store type:

   default value:
     define('SIMPLEID_STORE', 'filesystem');

   for dynalogin, use this value:
     define('SIMPLEID_STORE', 'dynalogin-filesystem');

