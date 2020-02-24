use ursa::{
    keys::{KeyGenOption, PrivateKey},
    signatures::{ed25519::Ed25519Sha512, SignatureScheme},
};

/// This library contains utilities to work with cryptographical keys.

/// If you need a keypair, use this method by default.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
/// [OsRng](https://docs.rs/rand/0.7/rand/rngs/struct.OsRng.html) random number generator is used.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    match Ed25519Sha512.keypair(Option::None) {
        Ok((public_key, private_key)) => Ok((public_key.0.clone(), private_key.0.clone())),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}

/// If you need a keypair and have a `seed`, use this method.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
/// [ChaChaRng](https://docs.rs/rand_chacha/0.2/rand_chacha/type.ChaChaRng.html) random number generator is used.
pub fn generate_keypair_with_seed(seed: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    match Ed25519Sha512.keypair(Option::Some(KeyGenOption::UseSeed(seed))) {
        Ok((public_key, private_key)) => Ok((public_key.0.clone(), private_key.0.clone())),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}

/// If you need a keypair and have a `secret key`, use this method.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
pub fn generate_keypair_with_secret_key(secret_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    match Ed25519Sha512.keypair(Option::Some(KeyGenOption::FromSecretKey(PrivateKey(
        secret_key,
    )))) {
        Ok((public_key, private_key)) => Ok((public_key.0.clone(), private_key.0.clone())),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}
