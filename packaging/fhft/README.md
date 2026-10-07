# flexisip-http-file-transfer-server, patched for PostgreSQL

The reference file store of chat attachments, run as is until the Elixir store
replaces it (docs/design/chat-media-plan.md, S0 and Part E).

Upstream: <https://github.com/BelledonneCommunications/flexisip-http-file-transfer-server>,
AGPL-3.0, at commit **`524ab71`**. The patch is against that commit.

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
