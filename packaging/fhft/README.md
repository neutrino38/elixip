# flexisip-http-file-transfer-server, patched for PostgreSQL

The reference file store of chat attachments, run as is until the Elixir store
replaces it (docs/design/chat-media-plan.md, S0 and Part E).

Upstream: <https://github.com/BelledonneCommunications/flexisip-http-file-transfer-server>,
AGPL-3.0, at commit **`524ab71`** (tag `1.1.1-alpha`). It is packaged here under
its own name, `bc-flexisip-http-file-transfer-server`: upstream's package,
slightly modified — the PDO patch, and the configuration of an AL9 host running
php-fpm.

## What is here

| File | Role |
|---|---|
| `bc-flexisip-http-file-transfer-server.spec` | the RPM: upstream's code at the pinned commit, the patch, the files below |
| `build-rpm.sh` | builds it in an `almalinux:9` container, into `packaging/dist/` |
| `common-pdo.patch` | PDO instead of mysqli (below); against upstream's tree, ready for a PR |
| `flexisip-http-file-transfer-server.conf` | the server config: digest on, realm from the `From`, PDO, logging off; `@…@` filled at install |
| `user.ini` | the PHP upload limits (64 MB), which php-fpm reads beside the scripts |
| `fhft.inc` | aliases, CORS for Trix, the upload directory's protections; loaded by the vhost only |
| `zz-fhft-vhost.conf` | the `files.weshwesh.eu` vhost, installed as a `.sample` |
| `rehearsal/` | the RPM installed in a container, against PostgreSQL (below) |

## Building

```bash
packaging/fhft/build-rpm.sh
# -> packaging/dist/bc-flexisip-http-file-transfer-server-1.1.1-0.alpha.0+524ab71.pdo1.el9.noarch.rpm
```

`Version` and the head of `Release` are what upstream's Makefile derives from
the commit (`1.1.1`, `0.alpha.0+524ab71`); **`.pdoN` counts our builds** of it:
+1 for every rebuild that leaves this machine, back to 1 when the commit
changes — `dnf install` of a NEVRA already installed keeps the old payload
(CLAUDE.md, "Changing the version").

Why not upstream's spec: it takes its version from `git describe`, depends on
`php-mysqlnd`, and installs an Apache config whose `php_value` lines only
`mod_php` reads — under php-fpm, AL9's default, httpd refuses them and does not
start. It also sends downloads through `download.php`, which challenges.

## Installing on web1

```bash
dnf install ./bc-flexisip-http-file-transfer-server-*.noarch.rpm php-pgsql
```

The package installs the scripts, the upload directory, the purge (upstream's
cron job, 02:00, files older than 7 days), logrotate, and on an SELinux host the
boolean and file context the store needs. What is left to the site:

1. **the read-only role** on the PostgreSQL server, and web1 in `pg_hba.conf`:

   ```sql
   CREATE ROLE fhft_ro LOGIN PASSWORD '<a password>';
   GRANT CONNECT ON DATABASE kamailio TO fhft_ro;
   GRANT USAGE ON SCHEMA public TO fhft_ro;
   GRANT SELECT (username, domain, ha1) ON subscriber TO fhft_ro;
   ```

2. **the five placeholders** of
   `/etc/flexisip-http-file-transfer-server/flexisip-http-file-transfer-server.conf`:

   | Placeholder | Value |
   |---|---|
   | `@AUTH_DB_DSN@` | `pgsql:host=<host>;port=5432;dbname=kamailio;sslmode=require` |
   | `@AUTH_DB_USER@`, `@AUTH_DB_PASSWORD@` | the role |
   | `@AUTH_ALGORITHM@` | `MD5`, or `SHA-256` if `[module.auth_db] password_hash = "sha256"` |
   | `@AUTH_NONCE_KEY@` | `openssl rand -hex 24` |

3. **the vhost**: copy `/etc/httpd/conf.d/zz-fhft-vhost.conf.sample` to
   `zz-fhft-vhost.conf`, set the wildcard certificate's two paths, then
   `apachectl configtest && systemctl reload httpd php-fpm`;
4. **DNS**: `files.weshwesh.eu`, `AAAA` (and `A`) to web1.

What installing it on web1 taught, on 2026-10-07:

- **`MD5` in capitals.** The PHP compares the algorithm `AUTH_QUERY` returns
  with `'MD5'` and `'SHA-256'`, case included. `'md5'` reads as an unknown
  algorithm: the 401 offers both challenges — the sign — and the upload then
  fails.
- **A managed base has no `pg_hba.conf`.** On Scaleway, web1 is let in by the
  instance's allowed IPs (`scw rdb acl add <ip>/32 …`) or a private network,
  the user is created in the console or by SQL, and the DSN takes the
  endpoint's host and port. Test from web1 with `psql` first: when it reads
  the row of an account, the PHP will.
- **`/var/opt` is `/opt` to SELinux.** The policy makes them equivalent and
  refuses a file context on the `/var/opt` path; the rules are written on
  `/opt/belledonne-communications/…`, which `.pdo2` does in `%post`. `.pdo1`
  left the upload directory `usr_t`, unwritable — by hand:

  ```bash
  semanage fcontext -a -t httpd_sys_rw_content_t '/opt/belledonne-communications/flexisip-http-file-transfer-tmp(/.*)?'
  semanage fcontext -a -t httpd_sys_rw_content_t '/opt/belledonne-communications/log(/.*)?'
  restorecon -Rv /var/opt/belledonne-communications
  ```

- **Diagnosing.** Logging is off; `LogLevel::DEBUG` in the config shows the
  whole request in `/var/opt/belledonne-communications/log/`, file names and
  digest headers included — set it back to `DISABLED` after. The vhost's own
  logs are two commented lines of its sample.

Then the checks of chat-media-plan S0: a 401 offering one challenge on the SIP
domain, a 204 to the CORS preflight, 403 on `/files/tmp/` and `download.php`, an
upload with a SIP account answering the XML, its file downloadable without
credentials.

## The rehearsal

```bash
packaging/fhft/build-rpm.sh
docker compose -f packaging/fhft/rehearsal/compose.yaml up -d --build
curl -s --digest -u alice:secret -H 'From: sip:alice@unit.test' \
  -F 'File=@photo.jpg;type=image/jpeg' http://localhost:8089/files/hft.php
docker compose -f packaging/fhft/rehearsal/compose.yaml down -v
```

The RPM installed on AL9 as on web1, in plain HTTP on port 8089, without cron;
PostgreSQL 16 with a kamailio-shaped `subscriber` table holding `alice` and
`bob` at `unit.test`, password `secret`, and the read-only role. What it showed
on 2026-10-07: one MD5 challenge, realm `unit.test`; an authenticated empty POST
answered **400**; the file served statically, byte for byte, `nosniff` and
`attachment`; a `.php` stored as `.php.txt`.

## `common-pdo.patch`

Upstream reads the subscriber base with `mysqli`, so MySQL only. The patch moves
`src/common.php` to PDO and documents the new key in the shipped config:

- `AUTH_DB_DSN`, when defined, names the base and its driver
  (`pgsql:host=…;dbname=…;sslmode=require`, or `mysql:…`);
- without it, the MySQL base of `AUTH_DB_HOST` and `AUTH_DB_NAME` is used, as
  before — an existing installation keeps working unchanged;
- `AUTH_DB_USER`, `AUTH_DB_PASSWORD`, `AUTH_QUERY` and
  `USE_PERSISTENT_CONNECTIONS` keep their meaning; the query, its two `?`
  (username, realm) and the rows it returns (`password`, `algorithm`) are
  upstream's.

It is against upstream's tree (`git apply` at the repository's root), so it can
be proposed upstream as it is. Against `auth_db`'s base, one algorithm for the
whole table, the query returns it as a constant, and the 401 offers that
challenge alone:

```php
define("AUTH_QUERY", "SELECT ha1 AS password, 'MD5' AS algorithm FROM subscriber WHERE username=? AND domain=? LIMIT 1");
```

The MySQL path without `AUTH_DB_DSN` was read, not run: the rehearsal runs
PostgreSQL only.
