## chiffre

### Description

**chiffre** helps you generate RSA key pairs as well as encrypt or decrypt files.

### Installation

#### Homebrew

```zsh
brew tap lucagoslar/homebrew-repo
brew install lucagoslar/homebrew-repo/chiffre
```

### Usage

If no output flag, `-o <PATH>` or `--output <PATH>`, was provided it defaults to your current location.

In case you already built and linked chiffre, replace `cargo run --` with `chiffre`.

#### Key pair generation

```zsh
cargo run -- -k <SIZE>
```

`-k` or `--keygen` only accepts integers larger than 0. Passing values smaller than 20 will result in chiffre exiting early and returning an error.

#### File encryption

```zsh
cargo run -- -i <FILE> --pub <FILE>
```

**Note:** Your key pair must be of a minimum length of 496 bits.

#### File decryption

```zsh
cargo run -- -i <FILE> --prv <FILE>
```
