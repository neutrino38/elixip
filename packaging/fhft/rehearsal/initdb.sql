-- A kamailio-shaped subscriber table, as auth_db reads it (ha1 = MD5 of
-- user:realm:password, realm = the SIP domain), and the read-only role the
-- file store uses. Test accounts: alice and bob @unit.test, password "secret".
CREATE TABLE subscriber (
    id       SERIAL PRIMARY KEY,
    username VARCHAR(64)  NOT NULL,
    domain   VARCHAR(190) NOT NULL,
    password VARCHAR(64)  NOT NULL DEFAULT '',
    ha1      VARCHAR(128) NOT NULL DEFAULT '',
    ha1b     VARCHAR(128) NOT NULL DEFAULT '',
    UNIQUE (username, domain)
);

INSERT INTO subscriber (username, domain, ha1) VALUES
    ('alice', 'unit.test', md5('alice:unit.test:secret')),
    ('bob',   'unit.test', md5('bob:unit.test:secret'));

CREATE ROLE fhft_ro LOGIN PASSWORD 'fhft_ro';
GRANT USAGE ON SCHEMA public TO fhft_ro;
GRANT SELECT (username, domain, ha1) ON subscriber TO fhft_ro;
