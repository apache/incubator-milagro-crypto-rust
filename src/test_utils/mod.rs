use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use crate::rand::RAND;

mod test_vector_structs;

pub use self::test_vector_structs::*;

pub fn printbinary(array: &[u8]) {
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}

pub fn create_rng() -> RAND {
    let mut raw: [u8; 100] = [0; 100];

    let mut rng = RAND::new();
    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }

    rng.seed(100, &raw);
    rng
}

// Reads the json test files
pub fn json_reader(file_name: &str) -> BufReader<File> {
    let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path_buf.push("src/test_utils/hash_to_curve_vectors/");
    let mut file_name = String::from(file_name);
    file_name.push_str(".json");
    file_path_buf.push(file_name);

    let file = File::open(file_path_buf).unwrap();
    BufReader::new(file)
}
