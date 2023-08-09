use std::{collections::HashMap, io::{stdin, stdout, Write}, env};

// Aother: Muhammed Alkohawaldeh
// github: <url>

fn main() {
    let hash_types: HashMap<String, i16> = HashMap::from([
        ("cksum (Unix)".to_string(), 32),
        ("CRC-16".to_string(), 16),
        ("CRC-32".to_string(), 32),
        ("CRC-32 MPEG-2".to_string(), 32),
        ("CRC-32C".to_string(), 32),
        ("CRC-64".to_string(), 64),
        ("Paul Hsieh's SuperFastHash".to_string(), 32),
        ("dhash".to_string(), 128),
        ("OSDB hash".to_string(), 64),
        ("BLAKE3".to_string(), 256),
        ("Poly1305-AES".to_string(), 128),
        ("BLAKE-256".to_string(), 256),
        ("BLAKE-256".to_string(), 256),
        ("BLAKE-512".to_string(), 512),
        ("GOST".to_string(), 256),
        ("HAS-160".to_string(), 160),
        ("MD2".to_string(), 128),
        ("MD4".to_string(), 128),
        ("MD5".to_string(), 128),
        ("MD6".to_string(), 512),
        ("RIPEMD".to_string(), 128),
        ("RIPEMD-128".to_string(), 128),
        ("RIPEMD-160".to_string(), 160),
        ("RIPEMD-320".to_string(), 320),
        ("SHA-1".to_string(), 160),
        ("SHA-224".to_string(), 224),
        ("SHA-256".to_string(), 256),
        ("SHA-384".to_string(), 384),
        ("SHA-512".to_string(), 512),
        ("Spectral Hash".to_string(), 512),
        ("SWIFFT".to_string(), 512),
        ("Tiger".to_string(), 192),
        ("Whirlpool".to_string(), 512),
    ]);
    
    let mut possible_hashes: Vec<&String> = Vec::new();
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

    for (key, value) in hash_types.iter(){
        if *value == hash_length{
            possible_hashes.push(key);
        }
    }
    println!("\nPossible hash types: ");

    for hash_ in possible_hashes.iter(){
    println!("\thash : {}", hash_);
    }
}
