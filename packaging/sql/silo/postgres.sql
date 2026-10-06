-- kelixip Silo schema, version 1 — PostgreSQL.
--
-- Run once by the operator, as an account allowed to create tables; the module
-- never runs DDL, and refuses to start when these tables are absent or at
-- another version. The module's own account needs SELECT, INSERT, UPDATE and
-- DELETE on the three tables and USAGE on the id sequence, nothing more.
--
-- Times are Unix seconds (BIGINT). The body is stored verbatim: a CPIM wrapper
-- and its IMDN fields go with it.

CREATE TABLE silo_version (
  version INTEGER NOT NULL
);

INSERT INTO silo_version (version) VALUES (1);

CREATE TABLE silo_message (
  id            BIGSERIAL     PRIMARY KEY,
  domain        VARCHAR(255)  NOT NULL,
  aor           VARCHAR(255)  NOT NULL,
  sender        VARCHAR(1024) NOT NULL,
  recipient     VARCHAR(1024) NOT NULL,
  content_type  VARCHAR(255)  NOT NULL,
  headers       TEXT          NOT NULL,
  body          BYTEA         NOT NULL,
  size          INTEGER       NOT NULL,
  received_at   BIGINT        NOT NULL,
  expires_at    BIGINT        NOT NULL,
  claimed_by    VARCHAR(255)  NULL,
  claimed_until BIGINT        NULL
);

CREATE INDEX silo_message_aor ON silo_message (domain, aor, id);
CREATE INDEX silo_message_expiry ON silo_message (expires_at);

CREATE TABLE silo_served (
  message_id BIGINT       NOT NULL,
  device     VARCHAR(512) NOT NULL,
  served_at  BIGINT       NOT NULL,
  PRIMARY KEY (message_id, device)
);
