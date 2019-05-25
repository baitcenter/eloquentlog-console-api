use chrono::{Utc, Duration};
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};

pub trait Claims
where Self: std::marker::Sized
{
    const ALGORITHM: Algorithm;
    const LEEWAY: i64;

    fn decode(
        token: &str,
        issuer: &str,
        secret: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error>;

    fn encode(
        subject: String,
        issuer: &str,
        kei_id: &str,
        secret: &str,
    ) -> String;

    fn get_subject(&self) -> String;
}

/// ActivationClaims
#[derive(Debug, Deserialize, Serialize)]
pub struct ActivationClaims {
    pub sub: String, // email
    pub iss: String,
    pub exp: usize,
}

impl Claims for ActivationClaims {
    const ALGORITHM: Algorithm = Algorithm::RS512;
    const LEEWAY: i64 = 36; // seconds

    fn decode(
        token: &str,
        issuer: &str,
        secret: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error>
    {
        let v = Validation {
            algorithms: vec![Self::ALGORITHM],
            iss: Some(issuer.to_string()),
            leeway: Self::LEEWAY,
            validate_exp: true,

            ..Validation::default()
        };
        // TODO
        // validate subject is email
        match decode::<Self>(&token, secret.as_ref(), &v) {
            Ok(v) => Ok(v.claims),
            Err(e) => Err(e),
        }
    }

    fn encode(
        subject: String,
        issuer: &str,
        key_id: &str,
        secret: &str,
    ) -> String
    {
        // TODO
        // iat (issue_at) and nbf (not before)
        let c = Self {
            sub: subject,
            iss: issuer.to_string(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };
        let mut h = Header::default();
        h.alg = Self::ALGORITHM;
        h.kid = Some(key_id.to_string());
        encode(&h, &c, secret.as_ref()).unwrap()
    }

    fn get_subject(&self) -> String {
        self.sub.to_string()
    }
}

/// AuthorizationClaims
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizationClaims {
    pub sub: String, // uuid
    pub iss: String,
    pub exp: usize,
}

impl Claims for AuthorizationClaims {
    const ALGORITHM: Algorithm = Algorithm::HS256;
    const LEEWAY: i64 = 36; // seconds

    fn decode(
        token: &str,
        issuer: &str,
        secret: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error>
    {
        let v = Validation {
            algorithms: vec![Self::ALGORITHM],
            iss: Some(issuer.to_string()),
            leeway: Self::LEEWAY,
            validate_exp: false,

            ..Validation::default()
        };

        // TODO
        // validate subject is uuid
        match decode::<Self>(&token, secret.as_ref(), &v) {
            Ok(v) => Ok(v.claims),
            Err(e) => Err(e),
        }
    }

    fn encode(
        subject: String,
        issuer: &str,
        key_id: &str,
        secret: &str,
    ) -> String
    {
        // TODO
        // iat (issue_at) and nbf (not before)
        let c = Self {
            sub: subject,
            iss: issuer.to_string(),
            exp: (Utc::now() + Duration::weeks(2)).timestamp() as usize,
        };
        let mut h = Header::default();
        h.alg = Self::ALGORITHM;
        h.kid = Some(key_id.to_string());
        encode(&h, &c, secret.as_ref()).unwrap()
    }

    fn get_subject(&self) -> String {
        self.sub.to_string()
    }
}