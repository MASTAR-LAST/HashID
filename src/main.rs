use std::{
    collections::HashMap,
    env,
    io::{stdin, stdout, Write},
};

// Aother: Muhammed Alkohawaldeh
// github: https://github.com/MASTAR-LAST/HashID

fn main() {
    let hash_types: HashMap<&str, i16> = HashMap::from([
        ("cksum (Unix)", 32),
        ("CRC-16", 16),
        ("CRC-32", 32),
        ("CRC-32 MPEG-2", 32),
        ("CRC-32C", 32),
        ("CRC-64", 64),
        ("Paul Hsieh's SuperFastHash", 32),
        ("dhash", 128),
        ("OSDB hash", 64),
        ("BLAKE3", 256),
        ("Poly1305-AES", 128),
        ("BLAKE-256", 256),
        ("BLAKE-256", 256),
        ("BLAKE-512", 512),
        ("GOST", 256),
        ("HAS-160", 160),
        ("MD2", 128),
        ("MD4", 128),
        ("MD5", 128),
        ("MD6", 512),
        ("RIPEMD", 128),
        ("RIPEMD-128", 128),
        ("RIPEMD-160", 160),
        ("RIPEMD-320", 320),
        ("SHA-1", 160),
        ("SHA-224", 224),
        ("SHA-256", 256),
        ("SHA-384", 384),
        ("SHA-512", 512),
        ("Spectral Hash", 512),
        ("SWIFFT", 512),
        ("Tiger", 192),
        ("Whirlpool", 512),
    ]);

    let mut possible_hashes: Vec<&&str> = Vec::new();
    let mut hash: String = String::new();

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        hash = args[1].clone();
    } else {
        print!("Enter your hash: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut hash).unwrap();
    }

    let hash_length: i16 = hash.trim().len() as i16;

    for (key, value) in hash_types.iter() {
        if *value == hash_length {
            possible_hashes.push(key);
        }
    }
    println!("\nPossible hash types: ");

    if possible_hashes.is_empty() {
        println!("\n\x1b[37;3mNo possible hashes found !")
    }

    for hash_ in possible_hashes.iter() {
        println!("\thash : {}", hash_);
    }
}
