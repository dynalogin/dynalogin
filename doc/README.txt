
dynalogin - OTP-based two-factor authentication suite
-----------------------------------------------------

Project aims:
-------------

- to enable the wider adoption of two-factor authentication
- to undermine the efforts of keystroke loggers and other trojans
- to reduce spam, by significantly increasing the effort
  required to make effective phishing attacks

Technical features:
-------------------

- privilege separation
  - OTP relies on storing unencrypted (not hashed) shared secrets for each
    user on a central server
  - the principle of privilege separation ensures that secrets are kept
    by a process that does authentication checks on behalf of other processes
  - calling processes never have access to the actual secrets, they just
    receive a yes/no answer to confirm if the OTP was validated
  
- reliable and scalable
  - use of various modular backends, e.g. flat file or ODBC/SQL

- convenient to deploy
  - written in C, to run on a wide variety of UNIX platforms
  - no dependency on other server products, although SQL databases
    can be used if desired

- low resource demands
  - written in C rather than Java

Components of the dynalogin suite:
----------------------------------

- dynalogin-datasource
    modules that can store and retrieve user data
    see libdynalogin/datasource for ODBC (SQL), file and sample datasources

- libdynalogin
    a controller for the dynalogin workflow, integrating the functionality
    of the datasources and the algorithms in the backend.
    libdynalogin provides a single API for the application developer
    to leverage all the backend features.

- dynalogind
    a daemon that can perform authentication of OTP credentials
    passed in over a socket, with support for TCP and TLS connections
    from client processes.

- libdynaloginclient
    a client library for processes that want to make network calls to
    dynalogind.  Supports TLS.

- pam_dynalogin
    a pam library that interacts with dynalogind over a TLS connection
    (using libdynaloginclient).  It can be stacked to allow fall-back
    to regular password authentication.

- dynalogin.php
    a PHP client library for accessing dynalogind over the network

- simpleid-store-dynalogin
    A module enabling the popular OpenID provider SimpleID to authenticate
    users against dynalogind

Further reading:
----------------

  To build from source, see BUILD.txt

  To experiment with and test the server, see TESTING.txt

  To learn more about back-end data source configuration, see
     libdynalogin/datasources/*/
  as there is an individual document for each data source.

  Some of the components have extra documents (*.txt) in their
  subdirectories.

