use crate::error::{Error, Result};
use base64_url::encode as b64encode;
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
        RSAKeyParameters, RSAKeyType,
    },
};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

macro_rules! now_usize {
    () => {
        chrono::Utc::now().timestamp() as usize
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    alg: String,
    iat: usize,
}

#[derive(Debug)]
struct RsaKeyPair {
    kid: Uuid,
    exp: usize,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

pub struct KeyGen {
    rsa_keys: HashMap<Uuid, RsaKeyPair>,
}

fn minutes_from_now(minutes: i64) -> usize {
    let now = Utc::now();
    (now - Duration::minutes(minutes)).timestamp() as usize
}

impl KeyGen {
    pub fn new() -> Result<Self> {
        let mut rsa_keys: HashMap<Uuid, RsaKeyPair> = HashMap::new();
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        let uuid = Uuid::new_v4();
        rsa_keys.insert(
            uuid,
            RsaKeyPair {
                kid: uuid,
                exp: minutes_from_now(30),
                private_key,
                public_key,
            },
        );

        let exp_private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let exp_public_key = RsaPublicKey::from(&exp_private_key);
        let exp_uuid = Uuid::new_v4();
        rsa_keys.insert(
            exp_uuid,
            RsaKeyPair {
                kid: exp_uuid,
                exp: minutes_from_now(-30),
                private_key: exp_private_key,
                public_key: exp_public_key,
            },
        );

        Ok(KeyGen { rsa_keys })
    }

    pub fn get_jwks(&self) -> JwkSet {
        let mut jwks = JwkSet { keys: Vec::new() };
        let now = now_usize!();
        for key_pair in self.rsa_keys.values() {
            if key_pair.exp > now {
                let n = key_pair.public_key.n().to_bytes_be();
                let e = key_pair.public_key.e().to_bytes_be();

                jwks.keys.push(Jwk {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Signature),
                        key_algorithm: Some(KeyAlgorithm::RS256),
                        key_id: Some(key_pair.kid.to_string()),
                        key_operations: None,
                        x509_url: None,
                        x509_chain: None,
                        x509_sha1_fingerprint: None,
                        x509_sha256_fingerprint: None,
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: RSAKeyType::RSA,
                        n: b64encode(&n),
                        e: b64encode(&e),
                    }),
                });
            }
        }
        jwks
    }

    pub fn generate_jwt(&self, expired: Option<bool>) -> Result<String> {
        let _expired = expired.unwrap_or(false);

        let iat = now_usize!();
        let key_pair = match self
            .rsa_keys
            .values()
            .into_iter()
            .find(|&x| !(_expired ^ (x.exp < iat)))
        {
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

#[cfg(test)]
#[path = "tests/test_keys.rs"]
mod test_keys;
