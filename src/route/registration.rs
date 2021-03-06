use chrono::{Duration, Utc};
use diesel::result::Error;
use fourche::queue::Queue;
use redis::{Commands, RedisError};
use rocket::State;
use rocket::http::Status;
use rocket_contrib::json::Json;
use rocket_slog::SyncLogger;

use crate::config::Config;
use crate::db::DbConn;
use crate::job::{Job, JobKind};
use crate::model::token::{VerificationClaims, Claims, TokenData};
use crate::model::user::{NewUser, User};
use crate::model::user_email::{NewUserEmail, UserEmail};
use crate::mq::MqConn;
use crate::response::Response;
use crate::request::user::registration::UserRegistration;
use crate::validation::user::Validator;
use crate::ss::SsConn;
use crate::util::split_token;

pub mod preflight {
    use rocket::response::Response as RawResponse;
    use crate::response::no_content_for;

    #[options("/register")]
    pub fn register<'a>() -> RawResponse<'a> {
        no_content_for("POST")
    }

    #[options("/deregister")]
    pub fn deregister<'a>() -> RawResponse<'a> {
        no_content_for("POST")
    }
}

#[post("/register", data = "<data>", format = "json")]
pub fn register<'a>(
    data: Json<UserRegistration>,
    db_conn: DbConn,
    mut mq_conn: MqConn,
    mut ss_conn: SsConn,
    logger: SyncLogger,
    config: State<Config>,
) -> Response<'a>
{
    // FIXME: create `account_registrar` service
    let res: Response = Default::default();

    let v = Validator::new(&db_conn, &data, &logger);
    match v.validate() {
        Err(errors) => {
            res.status(Status::UnprocessableEntity).format(json!({
                "errors": errors,
            }))
        },
        Ok(_) => {
            // TODO:
            // impl service object handles token generation/activation.
            // see also login
            let now = Utc::now();
            let granted_at = now.timestamp();
            let expires_at = (now + Duration::hours(1)).timestamp();

            let result: Result<(i64, String), Error> = db_conn
                .build_transaction()
                .serializable()
                .deferrable()
                .read_write()
                .run::<(i64, String), diesel::result::Error, _>(|| {
                    let mut u = NewUser::from(&data.0);
                    u.set_password(&data.password);
                    let user = User::insert(&u, &db_conn, &logger).unwrap();
                    let ue = NewUserEmail::from(&user);
                    let user_email =
                        UserEmail::insert(&ue, &db_conn, &logger).unwrap();

                    let data = TokenData {
                        value: UserEmail::generate_token(),
                        granted_at,
                        expires_at,
                    };
                    let raw_token = VerificationClaims::encode(
                        data,
                        &config.verification_token_issuer,
                        &config.verification_token_key_id,
                        &config.verification_token_secret,
                    );

                    if let Err(e) = user_email
                        .grant_token::<VerificationClaims>(
                            &raw_token,
                            &config.verification_token_issuer,
                            &config.verification_token_secret,
                            &db_conn,
                            &logger,
                        )
                    {
                        error!(logger, "error: {}", e);
                        return Err(Error::RollbackTransaction);
                    }
                    Ok((user_email.id, raw_token))
                });

            if let Ok((id, raw_token)) = result {
                if let Some((token, sign)) = split_token(raw_token) {
                    // TODO: use general value
                    let session_id = UserEmail::generate_token();
                    let key = format!("ur-{}", session_id);

                    // Instead of saving the signature into a cookie,
                    // putting it in session store.
                    //
                    // Because we need to make it available users to activate
                    // the account also via another device than signed up, so
                    // we can't rely on a cookie of http client (browser).
                    let result: Result<String, RedisError> = ss_conn
                        .set_ex(&key, sign, expires_at as usize)
                        .map_err(|e| {
                            error!(logger, "error: {}", e);
                            e
                        });

                    if result.is_ok() {
                        let job = Job::<String> {
                            kind: JobKind::SendUserActivationEmail,
                            args: vec![id.to_string(), session_id, token],
                        };
                        let mut queue = Queue::new("default", &mut mq_conn);
                        if let Err(err) = queue.enqueue::<Job<String>>(job) {
                            error!(logger, "error: {}", err);
                        } else {
                            return res;
                        }
                    }
                }
            }
            res.status(Status::InternalServerError).format(json!({
                "message": "Something wrong happen, sorry :'("
            }))
        },
    }
}

#[post("/deregister", format = "json")]
pub fn deregister(user: &User, logger: SyncLogger) -> Response {
    let res: Response = Default::default();

    // TODO
    info!(logger, "user: {}", user.uuid);

    res.status(Status::UnprocessableEntity)
}
