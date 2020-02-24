# ursa_key_utils

Standalone Key Generator for `Iroha` [Accounts](https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#account)
and [Peers](https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#peer).

## Usage

### Standalone

Download binary or build with `cargo build --release`.

```bash
ursa_key_utils 0.1
Soramitsu
ursa_key_utils is a command line arguments wrapper around `Ursa`.

USAGE:
    ursa_key_utils [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --secret <secret_key>    Sets a secret key. Should be used separately from `seed`.
        --seed <seed>            Sets a seed for random number generator. Should be used separately from `secret`.
```

## Functionality

- [ ] Generate keys for `Ed25519` using [Hyperledger Ursa](https://github.com/hyperledger/ursa).

## Use cases

- Standalone key generator for nodes and peers.
- As a library inside `Iroha 2`:
  - generate `peers` IDs when default hasn't been provided.

## Concerns

### Strong Random Number Generator

>> One thing to keep in mind is that when generating keys, they need to be done using a cryptographically secure random number generator.

`Ursa` provides an ability to generate pseudo random numbers via [BigNumber::rand](https://docs.rs/ursa/0.3.2/ursa/bn/struct.BigNumber.html#method.rand) which internally is [OpenSSL BigNumRef::rand](https://docs.rs/openssl/0.10.28/openssl/bn/struct.BigNumRef.html#method.rand).
