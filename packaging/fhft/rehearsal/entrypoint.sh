#!/bin/sh
# Fill the server config from the environment, then run php-fpm and httpd.
set -eu
conf=/etc/flexisip-http-file-transfer-server/flexisip-http-file-transfer-server.conf
sed -e "s|@AUTH_DB_DSN@|${AUTH_DB_DSN}|" \
    -e "s|@AUTH_DB_USER@|${AUTH_DB_USER}|" \
    -e "s|@AUTH_DB_PASSWORD@|${AUTH_DB_PASSWORD}|" \
    -e "s|@AUTH_ALGORITHM@|${AUTH_ALGORITHM:-MD5}|" \
    -e "s|@AUTH_NONCE_KEY@|$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')|" \
    "$conf.in" > "$conf"
chown root:apache "$conf"
chmod 0640 "$conf"

php-fpm -D
exec httpd -DFOREGROUND
