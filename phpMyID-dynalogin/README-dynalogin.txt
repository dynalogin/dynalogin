

Copy all files to the web server directory

Edit MyID.config.php
- change the username so that it matches a username 
  in the dynalogin user list
- update the dynalogind hostname and port, should
  match the details used by dynalogind

Rename MyID.config.php to index.php

WARNING:

Although digest authentication is used to protect
the one-time-password from a packet sniffer,
the phpMyID system relies on a session cookie
that can be sniffed just as easily as a password.

Therefore, it is recommended that this code
is hosted on an SSL/HTTPS webserver.

