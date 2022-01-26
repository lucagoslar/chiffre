fn encrypt(pubkey: rsa::RsaPublicKey, data: &[u8]) -> (Vec<u8>, [u8; 16], [u8; 16]) {
  let mut rng = rand::rngs::OsRng;

  let cipher = openssl::symm::Cipher::aes_128_cbc();
  let data = &*bytes;
  let key = rand::random::<[u8; 16]>();
  let iv = rand::random::<[u8; 16]>();

  let enc = match pubkey.encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, [&key, &iv].concat()[..]) {
    Ok(data) => data,
    Err(e) => panic!("{}", e),
  };

  return (enc, key, iv);
}