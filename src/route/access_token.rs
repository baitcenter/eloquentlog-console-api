use chrono::Utc;
use rocket::State;
use rocket::http::Status;
use rocket_slog::SyncLogger;

use crate::config::Config;
use crate::db::DbConn;
use crate::model::access_token::{AccessToken, AgentType};
use crate::model::token::{AuthenticationClaims, Claims, TokenData};
use crate::model::user::User;
use crate::response::Response;

pub mod preflight {
    use rocket::response::Response as RawResponse;
    use crate::response::no_content_for;

    #[options("/access_token/generate")]
    pub fn generate<'a>() -> RawResponse<'a> {
        no_content_for("GET")
    }

    #[options("/access_token/lrange")]
    pub fn lrange<'a>() -> RawResponse<'a> {
        no_content_for("GET")
    }
}

#[get("/access_token/generate")]
pub fn generate<'a>(
    user: &User,
    conn: DbConn,
    config: State<Config>,
    logger: SyncLogger,
) -> Response<'a>
{
    let res: Response = Default::default();

    info!(logger, "user: {}", user.uuid);

    match AccessToken::find_personal_token_by_user_id(user.id, &conn, &logger) {
        None => {
            error!(logger, "err: not found user.id {}", user.uuid);
            res.status(Status::NotFound)
        },
        Some(t) => {
            let value = if t.revoked_at.is_some() {
                "".to_string()
            } else {
                String::from_utf8(t.token.unwrap()).unwrap()
            };

            // this value is not saved
            let data = TokenData {
                value,
                granted_at: Utc::now().timestamp(),
                expires_at: 0,
            };
            let token = AuthenticationClaims::encode(
                data,
                &config.authentication_token_issuer,
                &config.authentication_token_key_id,
                &config.authentication_token_secret,
            );

            res.format(json!({"access_token": {
                "name": t.name,
                "token": token,
                "revoked_at": t.revoked_at,
                "created_at": t.created_at,
                "updated_at": t.updated_at,
            }}))
        },
    }
}

#[get("/access_token/hgetall/<key>")]
pub fn hgetall<'a>(
    key: AgentType,
    user: &User,
    conn: DbConn,
    _config: State<Config>,
    logger: SyncLogger,
) -> Response<'a>
{
    let res: Response = Default::default();

    info!(logger, "user: {}", user.uuid);
    info!(logger, "key: {}", key);

    if key != AgentType::Person {
        return res;
    }

    match AccessToken::find_personal_token_by_user_id(user.id, &conn, &logger) {
        None => {
            error!(logger, "err: not found user.id {}", user.uuid);
            res.status(Status::NotFound)
        },
        Some(t) => {
            // UUID?
            res.format(json!({"access_token": [
            t.name,
            {
                "name": t.name,
                "revoked_at": t.revoked_at,
                "created_at": t.created_at,
                "updated_at": t.updated_at,
            }]}))
        },
    }
}

#[get("/access_token/lrange/<key>/<start>/<stop>")]
pub fn lrange<'a>(
    key: AgentType,
    start: i64,
    stop: i64,
    user: &User,
    _conn: DbConn,
    _config: State<Config>,
    logger: SyncLogger,
) -> Response<'a>
{
    let res: Response = Default::default();

    info!(logger, "user: {}", user.uuid);
    info!(logger, "key: {}, start: {}, stop: {}", key, start, stop);

    if key != AgentType::Person {
        return res;
    }

    // TODO
    res
}
