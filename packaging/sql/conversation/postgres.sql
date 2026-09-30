-- kelixip conversation schema, version 1 — PostgreSQL.
--
-- Run once by the operator, as an account allowed to create tables. The module
-- never runs DDL, and refuses to start when these tables are absent or at
-- another version. Its own account needs SELECT, INSERT and DELETE on them.
--
-- One row per hibernated conversation, keyed on a hash of its key (domain,
-- rule, From AOR, To AOR), which the other columns spell out for listing.
-- `data` is what the script kept, in the Erlang external term format.

CREATE TABLE conversation_version (
  version INTEGER NOT NULL
);

INSERT INTO conversation_version (version) VALUES (1);

CREATE TABLE conversation (
  key_hash   CHAR(64)      PRIMARY KEY,
  domain     VARCHAR(255)  NOT NULL,
  chat_rule  VARCHAR(255)  NOT NULL,
  from_aor   VARCHAR(255)  NOT NULL,
  to_aor     VARCHAR(255)  NOT NULL,
  script     VARCHAR(1024) NOT NULL,
  resume     VARCHAR(255)  NOT NULL,
  data       BYTEA         NOT NULL,
  ttl        INTEGER       NOT NULL,
  expires_at BIGINT        NOT NULL
);

CREATE INDEX conversation_expiry ON conversation (expires_at);
