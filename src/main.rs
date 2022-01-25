use std::path::Path; // https://doc.rust-lang.org/std/path/struct.Path.html
use openssl::symm::{encrypt, Cipher}; // https://docs.rs/openssl/0.10.29/openssl/symm/index.html
use clap::Parser;
use rsa::{PublicKey, RsaPrivateKey, PaddingScheme, RsaPublicKey};
use rand::rngs::OsRng;

use std::io::Write;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    input: String,
    #[clap(short, long)]
    output: String,
    #[clap(short, long)]
    key: String,
}

fn main() {
    let args: Args = Args::parse();

    let mut rng: OsRng = OsRng;
    
    let bits: usize = 1028;

    let priv_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = RsaPublicKey::from(&priv_key);

    // Input file to bytes
    let bytes = match std::fs::read(args.input) {
        Ok(bytes) => bytes,
        Err(e) => panic!("{}", e),
    };

    // symmetric encryption setup
    let cipher = Cipher::aes_128_cbc();
    let data = &*bytes;
    let key = b"16x0000000000000";
    let iv = b"16x0000000000000";

    // encrypt bytes of input file symmetrically
    let ciphertext = encrypt(
        cipher,
        key,
        Some(iv),
        data).unwrap();

    // encrypt symmetric key with public key
    let enc_data = pub_key.encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &key[..]).expect("failed to encrypt");

    // https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/open.html
    // create a file instance to write to
    let mut dest= std::fs::OpenOptions::new()
    .write(true)
    .append(true)
    .open(Path::new("./main.rs.enc"))
    .unwrap();


    // write encrypted symmetric key to file
    match dest.write_all(&enc_data) {
        Ok(_) => println!("encrypted symmetric key written to destination"),
        Err(e) => panic!("{}", e),
    }

    // write encrypted bytes to file
    match dest.write_all(&ciphertext) {
        Ok(_) => println!("encrypted file written to destination"),
        Err(e) => panic!("{}", e),
    }

    println!("Done.");
}