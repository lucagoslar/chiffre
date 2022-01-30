mod lib;

use std::process;

use rsa::{pkcs8::{FromPublicKey, FromPrivateKey}, RsaPrivateKey};
use aes_gcm::aead::{Aead, NewAead};

struct Seperators<'a> {
    secret: &'a [u8],
    nonce: &'a [u8],
    file: &'a [u8]
}

fn main() {

    let seperators = Seperators {
        secret: b"--begin-secret--",
        nonce: b"--begin-nonce--",
        file: b"--begin-file--",
    };

    let args = clap::App::new("chiffre")
        .version("0.1.0")
        .author("Luca Goslar <git@lucagoslar.de>")
        .about("RSA file encryption and key pair generation")
        .long_about("chiffre helps you generate RSA key pairs as well as encrypt or decrypt files.")
        .override_usage("chiffre -k <BITS> (-o <OUT DIR>)\n    chiffre -i <FILE> --prv <FILE> (-o <OUT DIR>)\n    chiffre -i <FILE> --pub <FILE> (-o <OUT DIR>)")
        .arg(clap::Arg::new("INPUT")
            .short('i')
            .long("input")
            .value_name("FILE")
            .required(false)
            .takes_value(true)
            .number_of_values(1)
            .forbid_empty_values(true)
            .help("File to be encrypted or decrypted"))
        .arg(clap::Arg::new("OUTPUT")
            .short('o')
            .long("output")
            .value_name("OUT DIR")
            .required(false)
            .takes_value(true)
            .number_of_values(1)
            .forbid_empty_values(true)
            .default_value(".")
            .help("Directory new files will be created in"))
        .arg(clap::Arg::new("PUBKEY")
            .long("pub")
            .value_name("PUBLIC KEY")
            .required(false)
            .takes_value(true)
            .number_of_values(1)
            .forbid_empty_values(true)
            .required_unless_present("PRVKEY")
            .required_unless_present("KEYGEN")
            .help("Path to your public key file"))
        .arg(clap::Arg::new("PRVKEY")
            .long("prv")
            .value_name("PRIVATE KEY")
            .required(false)
            .takes_value(true)
            .number_of_values(1)
            .forbid_empty_values(true)
            .conflicts_with("PUBKEY")
            .required_unless_present("PUBKEY")
            .required_unless_present("KEYGEN")
            .help("Path to your private key file"))
        .arg(clap::Arg::new("KEYGEN")
            .short('k')
            .long("keygen")
            .value_name("BITS")
            .required(false)
            .takes_value(true)
            .number_of_values(1)
            .conflicts_with_all(&["PUBKEY", "PRVKEY", "INPUT"])
            .required_unless_present("PUBKEY")
            .required_unless_present("PRVKEY")
            .required_unless_present("INPUT")
            .help("Creates an RSA key pair of the given size"))
        .get_matches();

    // create ouput directory if not exist
    std::fs::create_dir_all(&args.value_of("OUTPUT").unwrap()).unwrap();

    if !&args.value_of("KEYGEN").is_none() {
        eprint!("Generating a key pair. ⚙️");

        // Sie of key pair to be generated
        let size = match args.value_of("KEYGEN").unwrap().parse::<usize>() {
            Ok(size) => size,
            Err(e) => {
                println!("\n\n💣 While reading key size: {}", e);
                process::exit(1);
            }
        };

        let rsakeypair = lib::rsa::keygen::rsakeygen(size);

        eprint!("\rKey pair generated. 🔐  \n");

        eprint!("Converting keys to a writable format. ⚙️");

        let pubkey = match rsa::pkcs8::ToPublicKey::to_public_key_pem(&rsakeypair.0) {
            Ok(key) => key,
            Err(e) => {
                println!("\n\n💣 While converting public key: {}", e);
                process::exit(1);
            }
        };
        
        let prvkey = match rsa::pkcs8::ToPrivateKey::to_pkcs8_pem(&rsakeypair.1) {
            Ok(key) => key,
            Err(e) => {
                println!("\n\n💣 While converting private key: {}", e);
                process::exit(1);
            },
        };

        eprint!("\rKey pair converted to a writable format. ⛓ \n");

        // Full destination path

        let pubpath = format!("{}/pub.pem", &args.value_of("OUTPUT").unwrap());
        let prvpath = format!("{}/prv.pem", &args.value_of("OUTPUT").unwrap());

        eprint!("Writing keys to disk. ⚙️");
        lib::write::write(&pubpath, &pubkey.as_bytes());
        lib::write::write(&prvpath, &prvkey.as_bytes());
        eprint!("\rKeys were written to disk. 💾\n");
        
        println!("\n✅ Successfully created a {} bit RSA key pair in \"{}\".", size, args.value_of("OUTPUT").unwrap());

        process::exit(1);
    }

    // Collect meta data on input file
    let inputmeta = match std::fs::metadata(&args.value_of("INPUT").unwrap()) {
        Ok(meta) => meta,
        Err(e) => {
            println!("💣 While reading input file: {}", e);
            process::exit(1);
        }
    };

    // Suffix that will be used to encrypt file
    let suffix = ".chiffre";

    // Extract filename from passed input path
    let filename = std::path::Path::new(args.value_of("INPUT").unwrap()).file_name().unwrap().to_str().unwrap();

    // Check passed path points to a file
    if !inputmeta.is_file() {
        println!("💣 While reading input file: Only files can be encrypted or decrypted.");
        process::exit(1);
    }

    // Reading input file
    let file = match std::fs::read(&args.value_of("INPUT").unwrap()) {
        Ok(content) => content,
        Err(e) => {
            println!("\n\n💣 While reading input file: {}", e);
            process::exit(1);
        },
    };

    match (&args.value_of("PUBKEY").is_none(), &args.value_of("PRVKEY").is_none(), &args.value_of("OUTPUT").is_none(), &args.value_of("INPUT").is_none()) {
        // Encrypt file
        (false, true, false, false) => {

            eprint!("Reading public key file. ⚙️");
            // Extract public key from file
            let pubkey = match std::fs::read(&args.value_of("PUBKEY").unwrap()) {
                Ok(data) => match rsa::RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&data[..])) {
                    Ok(key) => key,
                    Err(e) => {
                        println!("\n\n💣 While extracting public key: {}", e);
                        process::exit(1);
                    }
                },
                Err(e) => {
                    println!("\n\n💣 While reading public key file: {}", e);
                    process::exit(1);
                },
            };
            eprint!("\rPublic key file read and key extracted. 📖\n");

            eprint!("Encrypting file symmetrically with a randomly generated secret. ⚙️");

            // Generate a random key for symmetric encryption
            let key = rand::random::<[u8; 32]>();
            let aeskey = aes_gcm::Key::from_slice(&key);
            
            let cipher = aes_gcm::Aes256Gcm::new(aeskey); // Authenticated Encryption and Associated Data cipher bases on aes
            
            // Generate a random nonce for symmetric encryption
            let nonce = rand::random::<[u8; 12]>();
            let aesnonce = aes_gcm::Nonce::from_slice(&nonce);

            // Symmetric encryption of input file with randomly generated secret and nonce
            let ciphertext = match cipher.encrypt(aesnonce,&*file) {
                Ok(data) => data,
                Err(e) => {
                    println!("\n\n💣 While encrypting file: {}", e);
                    process::exit(1);
                },
            };

            eprint!("\rFile encrypted. 📦                                                 \n");

            let mut rng = rand::rngs::OsRng;
            
            eprint!("Encrypting secret. ⚙️");
            let keyenc = match rsa::PublicKey::encrypt(&pubkey, &mut rng, rsa::PaddingScheme::PKCS1v15Encrypt, &key[..]) {
                Ok(key) => key,
                Err(e) => {
                    println!("\n\n💣 While encrypting secret: {}", e);
                    process::exit(1);
                }
            };
            eprint!("\rRandomly generated secret encrypted. 📦\n");

            let nonceenc = match rsa::PublicKey::encrypt(&pubkey, &mut rng, rsa::PaddingScheme::PKCS1v15Encrypt, &nonce[..]) {
                Ok(key) => key,
                Err(e) => {
                    println!("\n💣 While encrypting nonce: {}", e);
                    process::exit(1);
                }
            };

            // Output path
            let fullpath = format!("{}/{}{}", &args.value_of("OUTPUT").unwrap(), &filename, &suffix);

            eprint!("Writing encrypted file to disk. ⚙️");
            // Write encrypted content to destination
            lib::write::write(&fullpath, &[seperators.secret.to_vec(), keyenc, seperators.nonce.to_vec(), nonceenc, seperators.file.to_vec(), ciphertext].concat()[..]);
            eprint!("\rEncrypted file was written to disk. 💾     ");

            println!("\n\n✅ Successfully encrypted file \"{}\". Find the encrypted file at \"{}\".", args.value_of("INPUT").unwrap(), fullpath);
        },

        // Decrypt file
        (true, false, false, false) => {
            eprint!("Reading private key file. ⚙️");
            // Extract private key from file
            let prvkey = match std::fs::read(&args.value_of("PRVKEY").unwrap()) {
                Ok(data) => match RsaPrivateKey::from_pkcs8_pem(&String::from_utf8_lossy(&data[..])) {
                    Ok(key) => key,
                    Err(e) => {
                        println!("\n\n💣 While extracting private key: {}", e);
                        process::exit(1);
                    },
                },
                Err(e) => {
                    println!("\n\n💣 While reading private key file: {}", e);
                    process::exit(1);
                },
            };
            eprint!("\rPrivate key file read and key extracted. 📖\n");

            eprint!("Decrypting content of file. ⚙️");

            // Extract parts of file

            let file_file_clone= std::clone::Clone::clone(&file);
            let file_file = file_file_clone.split_at(lib::helpers::index(&file[..], &seperators.file).unwrap());

            let file_nonce_clone = std::clone::Clone::clone(&file_file.0);
            let file_nonce = file_nonce_clone.split_at(lib::helpers::index(&file[..], &seperators.nonce).unwrap());

            let file_secret_clone = std::clone::Clone::clone(&file_nonce.0);
            let file_secret = file_secret_clone.split_at(lib::helpers::index(&file[..], &seperators.secret).unwrap());

            // Decrypt secret stored in file
            let secret = match prvkey.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &file_secret.1.split_at(seperators.secret[..].len()).1) {
                Ok(secret) => secret,
                Err(e) => {
                    println!("\n\n💣 While decrypting secret: {}", e);
                    process::exit(1);
                },
            };

            // Decrypt nonce stored in file
            let nonce = match prvkey.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &file_nonce.1.split_at( seperators.nonce[..].len()).1) {
                Ok(nonce) => nonce,
                Err(e) => {
                    println!("\n\n💣 While decrypting nonce: {}", e);
                    process::exit(1);
                },
            };

            // Decrypt file

            let aessecret = aes_gcm::Key::from_slice(&secret);
            let cipher = aes_gcm::Aes256Gcm::new(aessecret); // Authenticated Encryption and Associated Data cipher bases on aes
            let aes_nonce = aes_gcm::Nonce::from_slice(&nonce);

            let decipheredtext = match cipher.decrypt(aes_nonce,&*file_file.1.split_at(seperators.file[..].len()).1) {
                Ok(data) => data,
                Err(e) => {
                    println!("\n\n💣 While decrypting file: {}", e);
                    process::exit(1);
                },
            };

            eprint!("\rContent of file decrypted. 👓 \n");

            // Output path
            let fullpath = format!("{}/{}", &args.value_of("OUTPUT").unwrap(), &filename[0..(filename.len() - suffix.len())]);

            eprint!("Writing decrypted file to disk. ⚙️");
            // Write encrypted content to file
            lib::write::write(&fullpath, &decipheredtext);
            eprint!("\rDecrypted file was written to disk. 💾");

            println!("\n\n✅ Successfully decrypted file \"{}\". Find the decrypted file at \"{}\".", args.value_of("INPUT").unwrap(), fullpath);
        },

        (_, _, _, _) => {
            println!("💣 Could not process request: Make the flags passed were used correctly");
            process::exit(1);
        }
    };
}