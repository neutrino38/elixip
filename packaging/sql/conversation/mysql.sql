-- kelixip conversation schema, version 1 — MariaDB / MySQL (InnoDB).
--
-- Run once by the operator, as an account allowed to create tables. The module
-- never runs DDL, and refuses to start when these tables are absent or at
-- another version. Its own account needs SELECT, INSERT, UPDATE and DELETE on them
-- (UPDATE for the row lock a wake takes: SELECT ... FOR UPDATE).
--
-- One row per hibernated conversation, keyed on a hash of its key (domain,
-- rule, From AOR, To AOR), which the other columns spell out for listing.
-- `data` is what the script kept, in the Erlang external term format.

CREATE TABLE conversation_version (
  version INT NOT NULL
) ENGINE=InnoDB;

INSERT INTO conversation_version (version) VALUES (1);

CREATE TABLE conversation (
  key_hash   CHAR(64)      NOT NULL,
  domain     VARCHAR(255)  NOT NULL,
  chat_rule  VARCHAR(255)  NOT NULL,
  from_aor   VARCHAR(255)  NOT NULL,
  to_aor     VARCHAR(255)  NOT NULL,
  script     VARCHAR(1024) NOT NULL,
  resume     VARCHAR(255)  NOT NULL,
  data       LONGBLOB      NOT NULL,
  ttl        INT           NOT NULL,
  expires_at BIGINT        NOT NULL,
  PRIMARY KEY (key_hash),
  KEY conversation_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
