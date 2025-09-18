use super::*;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use rsa::pkcs1::EncodeRsaPublicKey;

#[test]
fn test_keygen_new() -> Result<()> {
    let now = now_usize!();
    let keygen = KeyGen::new()?;

    assert!(
        keygen.rsa_keys.len() == 2,
        "Found {} RSA keys instead of 2",
        keygen.rsa_keys.len()
    );
    assert!(
        keygen.rsa_keys.values().into_iter().any(|x| x.exp > now),
        "Found no non-expired RSA keys"
    );
    assert!(
        keygen.rsa_keys.values().into_iter().any(|x| x.exp < now),
        "Found no expired RSA keys"
    );
    Ok(())
}

fn _generate_and_validate_jwt(keygen: &KeyGen, expired: bool) -> Result<()> {
    let now = now_usize!();
    let jwt = keygen.generate_jwt(Some(expired))?;
    assert!(
        jwt.split(".").count() == 3,
        "JWT is not comprised of 3 parts: {}",
        jwt
    );

    let header = decode_header(&jwt).unwrap();
    let key_pair = keygen
        .rsa_keys
        .get(&Uuid::parse_str(&header.kid.unwrap()).unwrap())
        .unwrap();

    let pem = key_pair.public_key.to_pkcs1_pem(LineEnding::LF)?;

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
        !(expired ^ (decoded.as_ref().unwrap().claims.exp < now)),
        "Decoded does not have desired expiration: exp: {}, decoded: {:?}",
        expired,
        decoded.unwrap()
    );
    Ok(())
}

#[test]
fn test_generate_jwt() -> Result<()> {
    let keygen = KeyGen::new()?;
    _generate_and_validate_jwt(&keygen, false)?;
    Ok(())
}

#[test]
fn test_generate_jwt_expired() -> Result<()> {
    let keygen = KeyGen::new()?;
    _generate_and_validate_jwt(&keygen, true)?;
    Ok(())
}

#[test]
fn test_generate_jwt_failure() -> Result<()> {
    let mut keygen = KeyGen::new()?;
    keygen.rsa_keys.clear();
    assert!(_generate_and_validate_jwt(&keygen, false).is_err());
    Ok(())
}

#[test]
fn test_get_jwks() -> Result<()> {
    let now = now_usize!();
    let keygen = KeyGen::new()?;
    let jwt = keygen.generate_jwt(None)?;
    let jwks = keygen.get_jwks();

    // assert no expired
    for jwk in &jwks.keys {
        assert!(
            keygen
                .rsa_keys
                .get(&Uuid::parse_str(&jwk.common.key_id.as_ref().unwrap())?)
                .unwrap()
                .exp
                > now,
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
