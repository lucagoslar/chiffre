use std::process;

pub(crate) fn rsakeygen(size: usize) -> (rsa::RsaPublicKey, rsa::RsaPrivateKey) {

  let mut rng = rand::rngs::OsRng;

  let prvkey = match rsa::RsaPrivateKey::new(&mut rng, size) {
    Ok(key) => key,
    Err(e) => {
      println!("\n\n💣 While generating key pair: private key: {}", e);
      process::exit(1);
    },
  };
  
  let pubkey = rsa::RsaPublicKey::from(&prvkey);

  return (pubkey, prvkey);
}