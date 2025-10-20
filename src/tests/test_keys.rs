use super::*;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use rsa::pkcs1::EncodeRsaPublicKey;

fn _get_key(keygen: &KeyGen, expired: bool, kid: i64) -> Result<KeyRow> {
    let keys = keygen.get_keys(expired)?;

    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| Error::Custom(String::from("Error getting key")))?;
    Ok(key.clone())
}

#[test]
fn test_keygen_new() -> Result<()> {
    let keygen = KeyGen::new(true)?;

    assert!(
        keygen.get_keys(false)?.len() > 0,
        "No non-expired RSA keys found"
    );

    assert!(
        keygen.get_keys(true)?.len() > 0,
        "No expired RSA keys found"
    );

    Ok(())
}

fn _generate_and_validate_jwt(keygen: &KeyGen, expired: bool) -> Result<()> {
    let jwt = keygen.generate_jwt(expired)?;

    assert!(
        jwt.split(".").count() == 3,
        "JWT is not comprised of 3 parts: {}",
        jwt
    );

    let header = decode_header(&jwt).unwrap();
    let corresponding_key = _get_key(keygen, expired, header.kid.unwrap().parse::<i64>().unwrap())?;

    let pem = corresponding_key
        .key
        .to_public_key()
        .to_pkcs1_pem(LineEnding::LF)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;

    let decoded = decode::<Claims>(
        &jwt,
        &DecodingKey::from_rsa_pem(&pem.as_bytes())?,
        &validation,
    );

    assert!(
        decoded.is_ok(),
        "Failed to decode JWT: {:?}",
        decoded.is_ok()
    );

    assert!(
        !(expired ^ (decoded.as_ref().unwrap().claims.exp < Utc::now().timestamp() as usize)),
        "Decoded does not have desired expiration: exp: {}, decoded: {:?}",
        expired,
        decoded.unwrap()
    );

    Ok(())
}

#[test]
fn test_generate_jwt() -> Result<()> {
    let keygen = KeyGen::new(true)?;
    _generate_and_validate_jwt(&keygen, false)?;
    Ok(())
}

#[test]
fn test_generate_jwt_expired() -> Result<()> {
    let keygen = KeyGen::new(true)?;
    _generate_and_validate_jwt(&keygen, true)?;
    Ok(())
}

#[test]
fn test_generate_jwt_failure() -> Result<()> {
    let keygen = KeyGen::new(false)?;
    assert!(_generate_and_validate_jwt(&keygen, false).is_err());
    Ok(())
}

#[test]
fn test_get_jwks() -> Result<()> {
    let now = Utc::now().timestamp();
    let keygen = KeyGen::new(true)?;
    let jwt = keygen.generate_jwt(false)?;
    let jwks = keygen.get_jwks()?;

    // assert no expired
    for jwk in &jwks.keys {
        assert!(
            _get_key(
                &keygen,
                false,
                jwk.common.key_id.as_ref().unwrap().parse::<i64>().unwrap()
            )?
            .exp > now,
            "Found expired JWK in JWKs"
        );
    }

    let header = decode_header(&jwt)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|&jwk| jwk.common.key_id.as_ref().unwrap() == header.kid.as_ref().unwrap())
        .unwrap();

    let decoded = decode::<Claims>(
        &jwt,
        &DecodingKey::from_jwk(&jwk)?,
        &Validation::new(Algorithm::RS256),
    );
    assert!(decoded.is_ok(), "Failed to decode JWT: {:?}", decoded.err());
    Ok(())
}

#[test]
fn test_minutes_from_now() {
    minutes_from_now(30);
}
