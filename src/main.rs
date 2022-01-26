use std::io::Write;
use rsa::{PublicKey, RsaPrivateKey, PaddingScheme, RsaPublicKey};

/*
    Read keys from file: https://rust-by-example-ext.com/openssl/rsa.html
*/

fn main() {
    let args = clap::App::new("chiffre")
        .version("0.1.0")
        .author("Luca Goslar <git@lucagoslar.de>")
        .about("Encrypt and decrypt files.")
        .arg(clap::Arg::new("INPUT")
            .short('i')
            .long("input")
            .value_name("FILE")
            .required(true)
            .help("File to be en- or decrypted."))
        .arg(clap::Arg::new("OUTPUT")
            .short('o')
            .long("output")
            .value_name("OUT DIR")
            .required(true)
            .help("Directory the encrypted file will be created in."))
        .arg(clap::Arg::new("PUBLICKEY")
            .long("pub")
            .value_name("PUBLIC KEY")
            .required(false)
            .help("Path to your public key file."))
        .arg(clap::Arg::new("PRIVATEKEY")
            .long("prv")
            .value_name("PRIVATE KEY")
            .required(false)
            .help("Path to your private key file."))
        .get_matches();

    // collect meta on input
    let input_meta = match std::fs::metadata(&args.value_of("INPUT").unwrap()) {
        Ok(meta) => meta,
        Err(_) => {
            panic!("Could not locate input {}. Make sure it exists.", &args.value_of("INPUT").unwrap());
        }
    };

    // extract filename
    let pathname = std::path::Path::new(args.value_of("INPUT").unwrap()).file_name().unwrap().to_str().unwrap();

    // create ouput directory if not exist
    std::fs::create_dir_all(&args.value_of("OUTPUT").unwrap()).unwrap();

    // check if file to encrypt exists
    if !input_meta.is_file() {
        panic!("Input to encrypt is not of type file.");
    }


    let mut rng = rand::rngs::OsRng;
    
    let bits: usize = 1028;

    let priv_key = match RsaPrivateKey::new(&mut rng, bits) {
        Ok(key) => key,
        Err(_) => {
            panic!("Could not generate private key.");
        }
    };

    let pub_key = RsaPublicKey::from(&priv_key);

    // Input file to bytes
    let bytes = match std::fs::read(&args.value_of("INPUT").unwrap()) {
        Ok(bytes) => bytes,
        Err(e) => panic!("{}", e),
    };


    // symmetric encryption setup
    let cipher = openssl::symm::Cipher::aes_128_cbc();
    let data = &*bytes;
    let key = rand::random::<[u8; 16]>();
    let iv = rand::random::<[u8; 16]>();

    // encrypt bytes of input file symmetrically
    let ciphertext = match openssl::symm::encrypt(
        cipher,
        &key,
        Some(&iv),
        data
    ) {
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("{}", e),
    };

    // encrypt symmetric key with public key
    let enc_key = pub_key.encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &key[..]).expect("failed to encrypt");
    let enc_iv = pub_key.encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &iv[..]).expect("failed to encrypt");

    // suffix
    let suffix = ".enc";

    // full output path
    let fullpath = format!("{}/{}{}", &args.value_of("OUTPUT").unwrap(), &pathname, &suffix);

    if std::path::Path::new(&fullpath).exists() {
        match std::fs::remove_file(&fullpath) {
            Ok(_) => {},
            Err(e) => panic!("{}", e),
        };
    }

    let mut dest = match std::fs::File::create(&fullpath) {
        Ok(file) => file,
        Err(e) => panic!("{}", e),
    };

    // write encrypted symmetric key to file
    match dest.write_all(&enc_key) {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }

    // write encrypted symmetric iv to file
    match dest.write_all(&enc_iv) {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }

    // write encrypted bytes to file
    match dest.write_all(&ciphertext) {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }

    println!("Done.");
}