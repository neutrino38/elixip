# flexisip-http-file-transfer-server, patched for PostgreSQL

The reference file store of chat attachments, run as is until the Elixir store
replaces it (docs/design/chat-media-plan.md, S0 and Part E).

Upstream: <https://github.com/BelledonneCommunications/flexisip-http-file-transfer-server>,
AGPL-3.0, at commit **`524ab71`**. The patch is against that commit.

## What is here

| File | Goes to (web1, AL9) |
|---|---|
| `common-pdo.patch` | applied in `/opt/belledonne-communications/share/flexisip-http-file-transfer-server/` |
| `flexisip-http-file-transfer-server.conf` | `/etc/flexisip-http-file-transfer-server/`, `@…@` filled by hand, `root:apache 0640` |
| `user.ini` | `.user.ini` beside the scripts: the PHP limits, which php-fpm reads there |
| `fhft.inc` | `/etc/httpd/conf.d/fhft.inc`: aliases, CORS, the upload directory's protections |
| `zz-fhft-vhost.conf` | `/etc/httpd/conf.d/`: the `files.weshwesh.eu` vhost, `@WILDCARD@` = the certificate's file name |
| `rehearsal/` | the same files in containers, against PostgreSQL (below) |

The purge is upstream's `cron.d/flexisip-http-file-transfer-server`, copied as
shipped to `/etc/cron.d/`.

## The rehearsal

```bash
docker compose -f packaging/fhft/rehearsal/compose.yaml up -d --build
curl -s --digest -u alice:secret -H 'From: sip:alice@unit.test' \
  -F 'File=@photo.jpg;type=image/jpeg' http://localhost:8089/files/hft.php
docker compose -f packaging/fhft/rehearsal/compose.yaml down -v
```

AL9, httpd, php-fpm and the patched PHP, as on web1 but in plain HTTP on port
8089 and without the cron job; PostgreSQL 16 with a kamailio-shaped
`subscriber` table holding `alice` and `bob` at `unit.test`, password
`secret`, and the read-only role. What it showed on 2026-10-07: one MD5
challenge, realm `unit.test`; an authenticated empty POST answered **400**;
the file served statically, byte for byte, `nosniff` and `attachment`; a
`.php` stored as `.php.txt`.

## `common-pdo.patch`

Upstream reads the subscriber base with `mysqli`, so MySQL only. The patch
replaces it with PDO, the driver named by a new constant, `AUTH_DB_DSN`
(`pgsql:host=…;dbname=…;sslmode=require`, or `mysql:…`). `AUTH_DB_USER`,
`AUTH_DB_PASSWORD`, `AUTH_QUERY` and `USE_PERSISTENT_CONNECTIONS` keep their
meaning; `AUTH_DB_HOST` and `AUTH_DB_NAME` are no longer read. Nothing else
changes: the query, its two `?` (username, realm) and the rows it must return
(`password`, `algorithm`) are upstream's.

```bash
cd /opt/belledonne-communications/share/flexisip-http-file-transfer-server
sudo patch -p1 < common-pdo.patch
php -l common.php
```

Requires `php-pdo` and `php-pgsql` (AL9). Against `auth_db`'s base, a single
algorithm for the whole table, the query returns it as a constant:

```php
define("AUTH_QUERY", "SELECT ha1 AS password, 'MD5' AS algorithm FROM subscriber WHERE username=? AND domain=? LIMIT 1");
```

so the 401 offers that challenge alone.
