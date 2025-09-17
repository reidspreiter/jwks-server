use crate::error::{Error, Result};
use base64_url::encode as b64encode;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    alg: String,
    iat: usize,
}

struct RsaKeyPair {
    kid: Uuid,
    exp: usize,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

#[derive(Serialize)]
pub struct JWK {
    kty: String,
    kid: String,
    n: String,
    e: String,
    alg: String,
    r#use: String,
}

#[derive(Serialize)]
pub struct JWKSet {
    keys: Vec<JWK>,
}

pub struct KeyGen {
    rsa_keys: Vec<RsaKeyPair>,
}

fn minutes_from_now(minutes: i64) -> usize {
    let now = Utc::now();
    (now - Duration::minutes(minutes)).timestamp() as usize
}

impl KeyGen {
    pub fn new() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        let exp_private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let exp_public_key = RsaPublicKey::from(&exp_private_key);

        Ok(KeyGen {
            rsa_keys: vec![
                RsaKeyPair {
                    kid: Uuid::new_v4(),
                    exp: minutes_from_now(30),
                    private_key,
                    public_key,
                },
                RsaKeyPair {
                    kid: Uuid::new_v4(),
                    exp: minutes_from_now(-30),
                    private_key: exp_private_key,
                    public_key: exp_public_key,
                },
            ],
        })
    }

    pub fn get_jwks(&self) -> JWKSet {
        let mut jwks = JWKSet { keys: Vec::new() };
        let now = Utc::now().timestamp() as usize;
        for key_pair in &self.rsa_keys {
            if key_pair.exp > now {
                let n = key_pair.public_key.n().to_bytes_be();
                let e = key_pair.public_key.e().to_bytes_be();

                jwks.keys.push(JWK {
                    kty: String::from("RSA"),
                    kid: key_pair.kid.to_string(),
                    n: b64encode(&n),
                    e: b64encode(&e),
                    alg: String::from("RS256"),
                    r#use: String::from("sig"),
                });
            }
        }
        jwks
    }

    pub fn generate_jwt(&self, expired: Option<bool>) -> Result<String> {
        let _expired = expired.unwrap_or(false);

        let iat = Utc::now().timestamp() as usize;
        let key_pair = match self.rsa_keys.iter().find(|&x| !(_expired ^ (x.exp < iat))) {
            Some(p) => p,
            None => {
                return Err(Error::Custom(String::from(
                    "Could not find key with matching expiration",
                )));
            }
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_pair.kid.to_string());
        header.typ = Some(String::from("JWT"));

        let claims = Claims {
            exp: key_pair.exp,
            alg: String::from("RS256"),
            iat,
        };
        let pem = key_pair.private_key.to_pkcs1_pem(LineEnding::LF)?;
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(&pem.as_bytes())?,
        )?;
        Ok(token)
    }
}
