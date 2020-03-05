extern crate clap;

use clap::{App, Arg};

fn main() {
    use ursa_key_utils::*;
    let matches = App::new("ursa_key_utils")
        .version("0.1")
        .author("Soramitsu")
        .about("ursa_key_utils is a command line arguments wrapper around `Ursa`.")
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("seed")
                .help("Sets a seed for random number generator. Should be used separately from `secret`.")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("secret")
                .long("secret")
                .value_name("secret_key")
                .help("Sets a secret key. Should be used separately from `seed`.")
                .required(false)
                .takes_value(true)
        )
        .get_matches();
    let seed_option = matches.value_of("seed");
    let secret_option = matches.value_of("secret");
    if let Some(seed) = seed_option {
        let (public_key, private_key) = generate_keypair_with_seed(seed.as_bytes().into()).unwrap();
        println!("Public key: {}", &public_key);
        println!("Private key: {}", &private_key);
    } else if let Some(secret_key) = secret_option {
        let (public_key, private_key) =
            generate_keypair_with_secret_key(secret_key.as_bytes().into()).unwrap();
        println!("Public key: {}", &public_key);
        println!("Private key: {}", &private_key);
    } else {
        let (public_key, private_key) = generate_keypair().unwrap();
        println!("Public key: {}", &public_key);
        println!("Private key: {}", &private_key);
    }
}
