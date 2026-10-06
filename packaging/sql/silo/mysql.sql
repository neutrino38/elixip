-- kelixip Silo schema, version 1 — MariaDB / MySQL (InnoDB).
--
-- Run once by the operator, as an account allowed to create tables; the module
-- never runs DDL, and refuses to start when these tables are absent or at
-- another version. The module's own account needs SELECT, INSERT, UPDATE and
-- DELETE on the three tables, nothing more.
--
-- Times are Unix seconds (BIGINT). The body is stored verbatim: a CPIM wrapper
-- and its IMDN fields go with it.

CREATE TABLE silo_version (
  version INT NOT NULL
) ENGINE=InnoDB;

INSERT INTO silo_version (version) VALUES (1);

CREATE TABLE silo_message (
  id            BIGINT        NOT NULL AUTO_INCREMENT,
  domain        VARCHAR(255)  NOT NULL,
  aor           VARCHAR(255)  NOT NULL,
  sender        VARCHAR(1024) NOT NULL,
  recipient     VARCHAR(1024) NOT NULL,
  content_type  VARCHAR(255)  NOT NULL,
  headers       TEXT          NOT NULL,
  body          LONGBLOB      NOT NULL,
  size          INT           NOT NULL,
  received_at   BIGINT        NOT NULL,
  expires_at    BIGINT        NOT NULL,
  claimed_by    VARCHAR(255)  NULL,
  claimed_until BIGINT        NULL,
  PRIMARY KEY (id),
  KEY silo_message_aor (domain, aor, id),
  KEY silo_message_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE silo_served (
  message_id BIGINT       NOT NULL,
  device     VARCHAR(512) NOT NULL,
  served_at  BIGINT       NOT NULL,
  PRIMARY KEY (message_id, device)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
