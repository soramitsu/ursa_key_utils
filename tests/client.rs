#[cfg(test)]
mod tests {
    use ursa_key_utils::*;

    #[test]
    fn test_default_keys_generation() {
        let (public_key, private_key) = generate_keypair().expect("Failed to generate key pair.");
        dbg!(&public_key);
        dbg!(&private_key);
        assert!(!&public_key.is_empty());
        assert!(!&private_key.is_empty());
    }

    #[test]
    fn test_default_keys_generation_with_seed() {
        let (public_key, private_key) =
            generate_keypair_with_seed(vec![1, 2, 3]).expect("Failed to generate key pair.");
        dbg!(&public_key);
        dbg!(&private_key);
        assert!(!&public_key.is_empty());
        assert!(!&private_key.is_empty());
    }

    #[test]
    fn test_default_keys_generation_with_secret_key() {
        let (public_key, private_key) =
            generate_keypair_with_secret_key(vec![128; 64]).expect("Failed to generate key pair.");
        dbg!(&public_key);
        dbg!(&private_key);
        assert!(!&public_key.is_empty());
        assert!(!&private_key.is_empty());
    }
}
