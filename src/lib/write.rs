use std::process;

pub(crate) fn write(path: &String, bytes: &[u8]) {

  if std::path::Path::new(&path).exists() {
    match std::fs::remove_file(&path) {
      Ok(_) => {},
      Err(e) => {
        println!("\n\n💣 While removing file {}: {}", path, e);
        process::exit(1);
      },
    };
  }

  let mut file = match std::fs::File::create(&path) {
    Ok(file) => file,
    Err(e) => {
      println!("\n\n💣 While creating file {}: {}", path, e);
      process::exit(1);
    },
  };

  match std::io::Write::write_all(&mut file, bytes) {
    Ok(_) => {},
    Err(e) => {
      println!("\n\n💣 While writing file {}: {}", path, e);
      process::exit(1);
    },
  };
}