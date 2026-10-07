#!/bin/sh
# Fill the placeholders the RPM ships the server config with, from the
# environment, then run php-fpm and httpd.
set -eu
conf=/etc/flexisip-http-file-transfer-server/flexisip-http-file-transfer-server.conf
sed -i -e "s|@AUTH_DB_DSN@|${AUTH_DB_DSN}|" \
       -e "s|@AUTH_DB_USER@|${AUTH_DB_USER}|" \
       -e "s|@AUTH_DB_PASSWORD@|${AUTH_DB_PASSWORD}|" \
       -e "s|@AUTH_ALGORITHM@|${AUTH_ALGORITHM:-MD5}|" \
       -e "s|@AUTH_NONCE_KEY@|$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')|" \
       "$conf"

php-fpm -D
exec httpd -DFOREGROUND
