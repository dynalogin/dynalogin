

Copy *.php to /usr/local/share/dynalogin-phpmyid

Edit MyID.config.php
- change the username so that it matches a username 
  in the dynalogin user list
- update the dynalogind hostname and port, should
  match the details used by dynalogind

Add the following to the virtual host definition for your HTTPS host:

   AliasMatch ^/openid/(.*) /usr/local/share/dynalogin-phpmyid/MyID.config.php/$1
   <Directory "/usr/local/share/dynalogin-phpmyid/">
      AllowOverride None
      Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
      Order allow,deny
      Allow from all
   </Directory>

WARNING:

Although digest authentication is used to protect
the one-time-password from a packet sniffer,
the phpMyID system relies on a session cookie
that can be sniffed just as easily as a password.

Therefore, it is strongly recommended that this code
is hosted on an SSL/HTTPS webserver.

