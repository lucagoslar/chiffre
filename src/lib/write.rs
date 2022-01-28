pub(crate) fn write(path: &String, bytes: &[u8]) {

  if std::path::Path::new(&path).exists() {
    match std::fs::remove_file(&path) {
          Ok(_) => {},
          Err(e) => panic!("{}", e),
    };
  }

  let mut file = match std::fs::File::create(&path) {
      Ok(file) => file,
      Err(e) => panic!("{}", e),
  };

  match std::io::Write::write_all(&mut file, bytes) {
      Ok(_) => {},
      Err(e) => panic!("{}", e),
  };
}