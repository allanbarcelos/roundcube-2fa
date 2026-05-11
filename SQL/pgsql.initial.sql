CREATE TABLE IF NOT EXISTS roundcube_2fa (
  user_id integer NOT NULL,
  secret varchar(64) DEFAULT NULL,
  enabled smallint NOT NULL DEFAULT 0,
  backup_codes text DEFAULT NULL,
  PRIMARY KEY (user_id)
);
