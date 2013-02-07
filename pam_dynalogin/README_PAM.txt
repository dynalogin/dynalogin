
Installing the dynalogin PAM module (pam_dynalogin.so)
------------------------------------------------------

After installing the module with make install, it may be
necessary to take some of the following steps:

If you did not install to a location known to PAM, you may
need to copy the module to /lib/security or create a symlink, e.g:

# ln -s /opt/dynalogin/lib/security/pam_dynalogin.so /lib/security/

Add the module into /etc/pam.d/<some file>, e.g test with `su' command
by adding the following line at the top of /etc/pam.d/su:

auth requisite pam_dynalogin.so debug scheme=TOTP server=dynalogin-server.example.org port=9050 ca_file=/etc/ssl/certs/cacert.org.pem

After the above steps, it may be necessary to update PAM on some platforms:

# pam-auth-update --force


