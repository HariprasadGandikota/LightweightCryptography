use asconaead::verify;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::{self, BufRead};
//use std::path::Path;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex string")
}

fn main() -> io::Result<()>{
    let path = "LWC_AEAD_KAT_128_128.txt";
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut count: usize = 0;
    let mut key = [0u8;16];
    let mut nonce = [0u8;16];
    let mut pt = Vec::new();
    let mut ad = Vec::new();
    let mut ct = Vec::new();
    let mut avg_elapsed: Duration = Default::default();
    let mut avg_throughput: f64 = 0.0;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            if !key.is_empty() && !nonce.is_empty() && !ct.is_empty() {
                let start = Instant::now();
                let result = verify(&key.clone(), &nonce.clone(), &mut pt.clone(), &mut ad.clone(), &ct.clone());
                let elapsed = start.elapsed();
                if result {
                    //println!("Test Case {} Passed", count);
                } else {
                    //println!("Test Case {} Failed", count);
                }
                //println!("elapsed time is: {:?} ",elapsed);
                avg_elapsed += elapsed;
                let pt_size_mb = pt.len() as f64 / (1024.0 * 1024.0);
                let ad_size_mb = ad.len() as f64 / (1024.0 * 1024.0);
                avg_throughput += (pt_size_mb+ad_size_mb)/ elapsed.as_secs_f64();
            }
            key = [0u8;16];
            nonce = [0u8;16];
            pt.clear();
            ad.clear();
            ct.clear();
            continue;
        }
        if line.starts_with("Count = ") {
            count = line["Count = ".len()..].parse().unwrap();
        } else if line.starts_with("Key = ") {
            hex::decode_to_slice(&line["Key = ".len()..], &mut nonce).expect("Invalid hex string");
        } else if line.starts_with("Nonce = ") {
            hex::decode_to_slice(&line["Nonce = ".len()..], &mut nonce).expect("Invalid hex string");
        } else if line.starts_with("PT = ") {
            pt = hex_to_bytes(&line["PT = ".len()..]);
        } else if line.starts_with("AD = ") {
            ad = hex_to_bytes(&line["AD = ".len()..]);
        } else if line.starts_with("CT = ") {
            ct = hex_to_bytes(&line["CT = ".len()..]);
        }
    }
    // Ensure the last test case is processed if the file doesn't end with a blank line
    if !key.is_empty() && !nonce.is_empty() && !ct.is_empty() {
        let start = Instant::now();
        let result = verify(&key.clone(), &nonce.clone(), &mut pt.clone(), &mut ad.clone(), &ct.clone());
        let elapsed = start.elapsed();
        if result {
            println!("Test Case {} Passed", count);
        } else {
            println!("Test Case {} Failed", count);
        }
        println!("elapsed time is: {:?} ",elapsed);
        avg_elapsed += elapsed;
        let pt_size_mb = pt.len() as f64 / (1024.0 * 1024.0);
        let ad_size_mb = ad.len() as f64 / (1024.0 * 1024.0);
        avg_throughput += (pt_size_mb+ad_size_mb)/ elapsed.as_secs_f64();
    }
    avg_elapsed /= 1089;
    avg_throughput /= 1089.0;
    println!("average elapsed time for ascon128a for 1089 test cases is: {:?}", avg_elapsed);
    println!("average throughput for ascon128a for 1089 test cases is: {:.2?}mbps", avg_throughput);
    Ok(())
}