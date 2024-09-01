mod tinyjambu_variants;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::{self, BufRead};
//use std::path::Path;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex string")
}
fn main() {
    let path128 = "LWC_AEAD_KAT_128_96.txt";
    let path192 = "LWC_AEAD_KAT_192_96.txt";
    let path256 = "LWC_AEAD_KAT_256_96.txt";
    let benchmark128 = benchmark(path128, 128);
    eprintln!("{:?}",benchmark128);
    let benchmark192 = benchmark(path192, 192);
    eprintln!("{:?}", benchmark192);
    let benchmark256 = benchmark(path256, 256);
    eprintln!("{:?}", benchmark256);
}

fn benchmark(testcasefile: &str, size: usize) -> io::Result<()> {
    let path = testcasefile;
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut count: usize = 0;
    let mut key = Vec::new();
    let mut nonce = [0u8;12];
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
                let result: bool;
                if size==128 {
                    result = tinyjambu_variants::verify128(&key.clone().try_into().unwrap(), &nonce, &pt, &ad);
                }
                else if size==192 {
                    result = tinyjambu_variants::verify192(&key.clone().try_into().unwrap(), &nonce, &pt, &ad);
                }
                else {
                    result = tinyjambu_variants::verify256(&key.clone().try_into().unwrap(), &nonce, &pt, &ad);
                }
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
            key.clear();
            nonce = [0u8;12];
            pt.clear();
            ad.clear();
            ct.clear();
            continue;
        }
        if line.starts_with("Count = ") {
            count = line["Count = ".len()..].parse().unwrap();
        } else if line.starts_with("Key = ") {
            key = hex_to_bytes(&line["Key = ".len()..]);
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
    if !key.clone().is_empty() && !nonce.is_empty() && !ct.is_empty() {
        let start = Instant::now();
        let result: bool;
        if size==128 {
            result = tinyjambu_variants::verify128(&key.try_into().unwrap(), &nonce, &pt, &ad);
        }
        else if size==192 {
            result = tinyjambu_variants::verify192(&key.try_into().unwrap(), &nonce, &pt, &ad);
        }
        else {
            result = tinyjambu_variants::verify256(&key.try_into().unwrap(), &nonce, &pt, &ad);
        }
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
    println!("average elapsed time for tinyjambu{} for 1089 test cases is: {:?}", size, avg_elapsed);
    println!("average throughput for tinyjambu{} for 1089 test cases is: {:.2?}mbps", size, avg_throughput);
    Ok(())
}