use std::{
    convert::{TryFrom, TryInto},
    fmt,
    fmt::{Display, Error, Formatter},
};
use ursa::{
    keys::{KeyGenOption, PrivateKey},
    signatures::{ed25519::Ed25519Sha512, SignatureScheme},
};

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 64;

#[derive(Clone)]
pub struct Sha512PrivateKey([u8; PRIVATE_KEY_LENGTH]);

#[derive(Clone)]
pub struct Sha512PublicKey([u8; PUBLIC_KEY_LENGTH]);

impl From<&Sha512PrivateKey> for Vec<u8> {
    fn from(key: &Sha512PrivateKey) -> Self {
        key.0.to_vec()
    }
}

impl From<&Sha512PublicKey> for Vec<u8> {
    fn from(key: &Sha512PublicKey) -> Self {
        key.0.to_vec()
    }
}

impl TryFrom<&Vec<u8>> for Sha512PublicKey {
    type Error = String;

    fn try_from(vector: &Vec<u8>) -> Result<Self, Self::Error> {
        let array: [u8; PUBLIC_KEY_LENGTH] = (vector[..]).try_into().map_err(|_| {
            format!(
                "Sha512PublicKey: Wrong vector length. Expected {}. Got {}",
                PUBLIC_KEY_LENGTH,
                vector.len()
            )
        })?;
        Ok(Sha512PublicKey(array))
    }
}

impl TryFrom<&Vec<u8>> for Sha512PrivateKey {
    type Error = String;

    fn try_from(vector: &Vec<u8>) -> Result<Self, Self::Error> {
        if vector.len() == PRIVATE_KEY_LENGTH {
            let mut array = [0u8; PRIVATE_KEY_LENGTH];
            for (place, element) in array.iter_mut().zip(vector.iter()) {
                *place = *element;
            }
            Ok(Sha512PrivateKey(array))
        } else {
            Err(format!(
                "Sha512PrivateKey: Wrong vector length. Expected {}. Got {}",
                PRIVATE_KEY_LENGTH,
                vector.len()
            ))
        }
    }
}

impl Display for Sha512PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &Vec::from(self))
    }
}

impl Display for Sha512PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &Vec::from(self))
    }
}

/// This library contains utilities to work with cryptographical keys.

/// If you need a keypair, use this method by default.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
/// [OsRng](https://docs.rs/rand/0.7/rand/rngs/struct.OsRng.html) random number generator is used.
pub fn generate_keypair() -> Result<(Sha512PublicKey, Sha512PrivateKey), String> {
    match Ed25519Sha512.keypair(Option::None) {
        Ok((public_key, private_key)) => Ok((
            Sha512PublicKey::try_from(&public_key.0)?,
            Sha512PrivateKey::try_from(&private_key.0)?,
        )),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}

/// If you need a keypair and have a `seed`, use this method.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
/// [ChaChaRng](https://docs.rs/rand_chacha/0.2/rand_chacha/type.ChaChaRng.html) random number generator is used.
pub fn generate_keypair_with_seed(
    seed: Vec<u8>,
) -> Result<(Sha512PublicKey, Sha512PrivateKey), String> {
    match Ed25519Sha512.keypair(Option::Some(KeyGenOption::UseSeed(seed))) {
        Ok((public_key, private_key)) => Ok((
            Sha512PublicKey::try_from(&public_key.0)?,
            Sha512PrivateKey::try_from(&private_key.0)?,
        )),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}

/// If you need a keypair and have a `secret key`, use this method.
/// It uses [Ursa](https://docs.rs/ursa) library with `Ed25519` solution of [EdDSA](https://tools.ietf.org/html/rfc8032).
pub fn generate_keypair_with_secret_key(
    secret_key: Vec<u8>,
) -> Result<(Sha512PublicKey, Sha512PrivateKey), String> {
    match Ed25519Sha512.keypair(Option::Some(KeyGenOption::FromSecretKey(PrivateKey(
        secret_key,
    )))) {
        Ok((public_key, private_key)) => Ok((
            Sha512PublicKey::try_from(&public_key.0)?,
            Sha512PrivateKey::try_from(&private_key.0)?,
        )),
        Err(e) => Err(format!("Failed to generate keypair: {}.", e)),
    }
}
