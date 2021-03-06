DROP INDEX IF EXISTS users_state_idx;
DROP INDEX IF EXISTS users_reset_password_state_idx;

DROP INDEX IF EXISTS users_uuid_idx;
DROP INDEX IF EXISTS users_username_idx;
DROP INDEX IF EXISTS users_reset_password_token_idx;
DROP INDEX IF EXISTS users_email_idx;

DROP TABLE IF EXISTS users;
DROP SEQUENCE IF EXISTS users_id_seq;

DROP TYPE IF EXISTS e_user_state;
DROP TYPE IF EXISTS e_user_reset_password_state;

-- (REQUIRE SUPERUSER)
DROP EXTENSION IF EXISTS "uuid-ossp";
