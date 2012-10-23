

Project aims:
- to enable the wider adoption of two-factor authentication
- to undermine the efforts of keystroke loggers and other trojans
- to reduce spam, by significantly increasing the effort
  required to make effective phishing attacks

Technical features:
- privilege separation
  - secrets are kept by a process that does authentication checks
  - calling processes never have access to the actual secrets
- reliable and scalable
  - use of various modular backends, e.g. flat file or ODBC/SQL
- convenient to deploy
  - written in C, to run on a wide variety of UNIX platforms
  - no dependency on other server products, although SQL databases
    can be used if desired
- low resource demands
  - written in C rather than Java

Architecture:
- dynalogin-datasource
    modules that can store and retrieve user data
- libhotp
    implementation of the HOTP algorithm (from hotp-toolkit)
- libdynalogin
    a controller for the dynalogin process, integrating the functionality
    of the datasources and the algorithms in the backend
    libdynalogin provides a single API for the application developer
    to leverage all the backend features
- dynalogind
    a daemon that can perform authentication of OTP credentials
    passed in over a socket
- libdynaloginclient
    a client library for dynalogind
- jdynalogin
    a client library for dynalogind
- libpamdynalogin
    a pam library that interacts with dynalogind
- dynaloginapp
    a webapp offering the features of an OpenID provider with dynalogin

Further reading:

  To build from source, see BUILD.txt

  To experiment with and test the server, see TESTING.txt

  To learn more about back-end data source configuration, see
     libdynalogin/datasources/*/
  as there is an individual document for each data source.
