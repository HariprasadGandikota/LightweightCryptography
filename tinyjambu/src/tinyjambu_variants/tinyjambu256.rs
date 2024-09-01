const FRAMEBITS_IV: u32 = 0x00000010;
const FRAMEBITS_AD: u32 = 0x00000030;
const FRAMEBITS_ENC: u32 = 0x00000050;
const FRAMEBITS_FINAL: u32 = 0x00000070;
const MAX_ROUNDS: usize = 1280;
const MIN_ROUNDS: usize = 640;

fn u8_to_u32_array(u8_array: &[u8]) -> Vec<u32> {
    // Ensure the input array's length is a multiple of 4
    assert!(u8_array.len() % 4 == 0, "Input length must be a multiple of 4");

    u8_array
        .chunks(4)  // Break the array into chunks of 4 bytes
        .map(|chunk| {
            // Combine 4 u8 elements into a single u32
            let mut array = [0u8; 4];
            array.copy_from_slice(chunk);
            u32::from_be_bytes(array)  // Convert the array to a u32 using little-endian byte order
        })
        .collect()  // Collect the result into a Vec<u32>
}
pub struct TinyjambuAead {
    key: [u8;32],
    nonce: [u8;12],
    state: [u32;4],
}
impl TinyjambuAead {
    pub fn new(key: &[u8;32], nonce: &[u8;12]) -> Self {
        Self { key: *key,
            nonce: *nonce,
            state: [0u32;4],
        }
    }
    pub fn init(&mut self) {
        let u32_nonce: [u32;3] = u8_to_u32_array(&self.nonce).try_into().unwrap();
        self.state_update(MAX_ROUNDS);
        for i in 0..3 {
            self.state[2] ^= FRAMEBITS_IV;
            self.state_update(MIN_ROUNDS);
            self.state[0] ^= u32_nonce[i];
        }
        //println!("state after init {:0x?} ", self.state);
    }
    fn state_update(&mut self, rounds: usize) {
        let u32_key: [u32;8] = u8_to_u32_array(&self.key).try_into().unwrap();
        for i in 0..(rounds>>5) {
            let b47 = (self.state[1] >> 15) | (self.state[2] << 17);
            let b70 = (self.state[2] >> 6) | (self.state[3] << 26);
            let b85 = (self.state[2] >> 21) | (self.state[3] << 11);
            let b91 = (self.state[2] >> 27) | (self.state[3] << 5);
            let feedback = self.state[0] ^ b47 ^ (!(b70 & b85)) ^ b91 ^ u32_key[i&3];
            self.state[0] = self.state[1];
            self.state[1] = self.state[2];
            self.state[2] = self.state[3];
            self.state[3] = feedback;
        }
    }
    pub fn process_ad(&mut self, ad: &Vec<u8>) {
        for i in 0..(ad.len()>>2) {
            self.state[2] ^= FRAMEBITS_AD;
            self.state_update(MIN_ROUNDS);
            self.state[0] ^= u32::from_be_bytes(ad[i*4..i*4+4].try_into().unwrap());
        }
        if (ad.len()&3) > 0 {
            self.state[2] ^= FRAMEBITS_AD;
            self.state_update(MIN_ROUNDS);
            for j in 0..(ad.len()&3) {
                self.state[0] ^= (ad[ad.len() - ad.len()&3 + j] as u32) << j*8;
            }
            self.state[2] ^= (ad.len()&3) as u32;
        }
        //println!("state after process ad {:?} ", self.state);
    }
    pub fn encrypt(&mut self, plaintext: &Vec<u8>) -> Vec<u8>{
        let pt_len = plaintext.len();
        let mut ciphertext: Vec<u8> = vec![0u8;pt_len];
        for i in 0..(pt_len>>2) {
            self.state[2] ^= FRAMEBITS_ENC;
            self.state_update(MAX_ROUNDS);
            let ind = pt_len-4*(i+1);
            let u32_pt = u32::from_be_bytes(plaintext[ind..ind+4].try_into().unwrap());
            self.state[0] ^= u32_pt;
            let u8_ct = (self.state[1] ^ u32_pt).to_be_bytes();
            for j in 0..4 {
                ciphertext[ind+j] = u8_ct[j];
            }
        }
        if (pt_len&3) > 0 {
            self.state[2] ^= FRAMEBITS_ENC;
            self.state_update(MAX_ROUNDS);
            let ind = pt_len&3;
            for j in 0..ind {
                self.state[0] ^= (plaintext[ind-1-j] as u32) << j*8;
                ciphertext[ind-1-j] = (((self.state[1] << 24-j*8) >> 24) as u8) ^ plaintext[ind-1-j];
            }
            self.state[2] ^= ind as u32;
        }
        ciphertext
    }
    pub fn decrypt(&mut self, ciphertext: &Vec<u8>) -> Vec<u8>{
        let ct_len = ciphertext.len();
        let mut plaintext: Vec<u8> = vec![0u8;ct_len];
        for i in 0..(ct_len>>2) {
            self.state[2] ^= FRAMEBITS_ENC;
            self.state_update(MAX_ROUNDS);
            let ind = ct_len-4*(i+1);
            let u32_ct = u32::from_be_bytes(ciphertext[ind..ind+4].try_into().unwrap());
            let u8_pt = (self.state[1] ^ u32_ct).to_be_bytes();
            for j in 0..4 {
                plaintext[ind+j] = u8_pt[j];
            }
            self.state[0] ^= u32::from_be_bytes(u8_pt.try_into().unwrap());
        }
        if (ct_len&3) > 0 {
            self.state[2] ^= FRAMEBITS_ENC;
            self.state_update(MAX_ROUNDS);
            let ind = ct_len&3;
            for j in 0..(ct_len&3) {
                plaintext[ind-1-j] = (((self.state[1] << 24-j*8) >> 24) as u8) ^ ciphertext[ind-1-j];
                self.state[0] ^= (plaintext[ind-1-j] as u32) << j*8;
            }
            self.state[2] ^= ind as u32;
        }
        plaintext
    }
    pub fn finalization(&mut self) -> [u32;2] {
        let mut tag: [u32;2] = [0u32;2];
        self.state[2] ^= FRAMEBITS_FINAL;
        self.state_update(MAX_ROUNDS);
        tag[0] = self.state[3];
        self.state[2] ^= FRAMEBITS_FINAL;
        self.state_update(MIN_ROUNDS);
        tag[1] = self.state[3];
        tag
    }
}

pub fn verify256(key: &[u8;32], nonce: &[u8;12], pt: &Vec<u8>, ad: &Vec<u8>) -> bool {
    let mut enc = TinyjambuAead::new(key, nonce);
    enc.init();
    enc.process_ad(&ad);
    //println!("pt = {:?} ", pt);
    let ciphertext = enc.encrypt(&pt);
    let tag = enc.finalization();
    //println!("ciphertext = {:0x?}", ciphertext);
    //println!("tag = {:0x?}", tag);
    let mut dec = TinyjambuAead::new(key, nonce);
    dec.init();
    dec.process_ad(&ad);
    let _message = dec.decrypt(&ciphertext);
    let new_tag = dec.finalization();
    //println!("message = {:0x?}", message);
    //println!("new_tag = {:0x?}", new_tag);
    assert_eq!(tag, new_tag);
    //assert_eq!(pt, &message);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn it_works() {
        let key: [u8;32] = (hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").expect("Decoding failed")).as_slice().try_into().expect("incorrect length");
        let nonce: [u8;12] = (hex::decode("000102030405060708090A0B").expect("Decoding failed")).as_slice().try_into().expect("incorrect length");
        let pt = hex::decode("").expect("Decoding failed");
        let ad = hex::decode("").expect("Decoding failed");
        let _ct = "ED7B37CC6E9BDC7B".to_string();
        let start = Instant::now();
        let mut enc = TinyjambuAead::new(&key, &nonce);
        enc.init();
        enc.process_ad(&ad);
        //println!("pt = {:?} ", pt);
        let ciphertext = enc.encrypt(&pt);
        let tag = enc.finalization();
        //println!("ciphertext = {:0x?}", ciphertext);
        //println!("tag = {:0x?}", tag);
        let mut dec = TinyjambuAead::new(&key, &nonce);
        dec.init();
        dec.process_ad(&ad);
        let _message = dec.decrypt(&ciphertext);
        let new_tag = dec.finalization();
        //println!("message = {:0x?}", message);
        //println!("new_tag = {:0x?}", new_tag);
        assert_eq!(tag, new_tag);
        let elapsed = start.elapsed();
        println!("elapsed time : {:?}", elapsed);
    }
}
