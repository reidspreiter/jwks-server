use super::*;

#[test]
fn test_custom_error() {
    Error::Custom("Custom error".to_string());
    let _ = Error::custom("gipple");
}

#[test]
fn test_from_error() {
    let _ = Error::from(std::fmt::Error);
    let _ = Error::from(rsa::errors::Error::Decryption);
    let _ = Error::from(rsa::pkcs1::Error::Version);
}

#[test]
fn test_display() {
    let e = Error::Custom("Custom Error".to_string());
    let _ = format!("{:?}", e);
    let _ = format!("{}", e);
}

#[test]
fn test_into_error() {
    let e = Error::Custom("bingus".to_string());
    let io_err: std::io::Error = e.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
}
