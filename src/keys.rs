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
    RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

fn minutes_from_now(minutes: i64) -> i64 {
    let now = Utc::now();
    (now - Duration::minutes(minutes)).timestamp()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    alg: String,
    iat: usize,
}

#[derive(Clone)]
struct KeyRow {
    kid: i64,
    key: RsaPrivateKey,
    exp: i64,
}

pub struct KeyGen {
    db_path: &'static str,
}

impl KeyGen {
    fn get_keys(&self, expired: bool) -> Result<Vec<KeyRow>> {
        let now = Utc::now().timestamp();
        let conn = Connection::open(self.db_path)?;

        let mut stmt = conn.prepare(
            "SELECT kid, key, exp FROM keys WHERE CASE WHEN ?1 THEN exp <= ?2 ELSE exp > ?2 END",
        )?;
        let rows = stmt.query_map(rusqlite::params![expired, now], |row| {
            let kid: i64 = row.get(0)?;
            let key_blob: Vec<u8> = row.get(1)?;
            let exp: i64 = row.get(2)?;

            let key = RsaPrivateKey::from_pkcs1_der(&key_blob).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })?;
            Ok(KeyRow { kid, key, exp })
        })?;

        let mut keys = Vec::new();
        for key in rows {
            keys.push(key?);
        }

        Ok(keys)
    }

    pub fn generate_new_rsa(&self, exp_minutes: i64) -> Result<()> {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let conn = Connection::open(self.db_path)?;
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (
                key.to_pkcs1_der()?.as_bytes(),
                minutes_from_now(exp_minutes),
            ),
        )?;
        Ok(())
    }

    pub fn new(initialize_keys: bool) -> Result<Self> {
        let db_path = "totally_not_my_privateKeys.db";
        let conn = Connection::open(db_path)?;

        conn.execute("DROP TABLE IF EXISTS keys", ())?;
        conn.execute(
            "CREATE TABLE keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )",
            (),
        )?;

        let keygen = KeyGen { db_path };

        log::info!("Initializing keys...");
        if initialize_keys {
            keygen.generate_new_rsa(120)?;
            keygen.generate_new_rsa(-120)?;
        }

        Ok(keygen)
    }

    pub fn get_jwks(&self) -> Result<JwkSet> {
        let mut jwks = JwkSet { keys: Vec::new() };

        for key in self.get_keys(false)? {
            let pub_key = key.key.to_public_key();
            let n = pub_key.n().to_bytes_be();
            let e = pub_key.e().to_bytes_be();

            jwks.keys.push(Jwk {
                common: CommonParameters {
                    public_key_use: Some(PublicKeyUse::Signature),
                    key_algorithm: Some(KeyAlgorithm::RS256),
                    key_id: Some(key.kid.to_string()),
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
        Ok(jwks)
    }

    pub fn generate_jwt(&self, expired: bool) -> Result<String> {
        let iat = Utc::now().timestamp() as usize;

        let keys = self.get_keys(expired)?;
        let key = keys
            .get(0)
            .ok_or_else(|| Error::Custom(String::from("Found no keys")))?;

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.kid.to_string());
        header.typ = Some(String::from("JWT"));

        let claims = Claims {
            exp: key.exp as usize,
            alg: String::from("RS256"),
            iat,
        };

        let pem = key.key.to_pkcs1_pem(LineEnding::LF)?;

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
