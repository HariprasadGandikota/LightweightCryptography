const _RH :usize = 64;
const RB :usize = 1;
const SH :usize = 12;
const SB :usize = 1;
const SE :usize = 6;
const SK :usize = 12;
const N :usize = 40;
const K :usize = 16;

pub struct IsapAead {
    key: [u64;2],
    nonce: [u64;2],
}

impl IsapAead {
    pub fn new(key: [u8;16], nonce: [u8;16]) -> Self {
        Self { key: [u64::from_be_bytes(key[0..8].try_into().unwrap()), u64::from_be_bytes(key[8..16].try_into().unwrap())],
            nonce: [u64::from_be_bytes(nonce[0..8].try_into().unwrap()), u64::from_be_bytes(nonce[8..16].try_into().unwrap())]
        }
    }
    pub fn ascon_permutation(state: &mut [u64;5], rounds: usize) {
        for i in 0..rounds {
            Self::constant_add(state, i, rounds);
            Self::substitution(state);
            Self::linear_diffusion(state);
        }
    }
    // performs ascon substitution function.
    fn substitution(state: &mut [u64]) {
        state[0] ^= state[4];
        state[2] ^= state[1];
        state[4] ^= state[3];
        let old_state0 = state[0];
        let old_state4 = state[4];
        state[4] ^= !state[0] & state[1];
        state[0] ^= !state[1] & state[2];
        state[1] ^= !state[2] & state[3];
        state[2] ^= !state[3] & old_state4;
        state[3] ^= !old_state4 & old_state0;
        state[1] ^= state[0];
        state[3] ^= state[2];
        state[0] ^= state[4];
        state[2] = !state[2];
    }
    // performs ascon constant addition function.
    fn constant_add(state: &mut [u64], round: usize, rounds: usize) {
        let round_const: [u64; 12] = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b];
        state[2] ^= round_const[12 - rounds + round];
    }
    // performs ascon linear diffusion function.
    fn linear_diffusion(state: &mut [u64]) {
        let rotate_index = [[19,28],[61,39],[1,6],[10,17],[7,41]];
        for i in 0..5 {
            state[i] ^= state[i].rotate_right(rotate_index[i][0]) ^ state[i].rotate_right(rotate_index[i][1]);
        }
    }
    pub fn re_key(&self, enc: bool, string_y: &[u64;2]) -> Vec<u64> {
        let iv;
        let iv_ke = [0x038040010c01060c, 0, 0];
        let iv_ka = [0x028040010c01060c, 0, 0];
        let z;
        let mut state: [u64;5] = [0;5];
        // init
        if enc {
            // encryption
            iv = iv_ke;
            z = N-K;
        }
        else {
            // hash
            iv = iv_ka;
            z = K;
        }
        for i in 0..2 {
            state[i] = self.key[i];
        }
        for i in 0..3 {
            state[2+i] = iv[i];
        }
        Self::ascon_permutation(&mut state, SK);
        // absorb
        for i in 0..(string_y.len()*8/RB)-1 {
            let rem = i%64;
            let quo = i/64;
            state[0] ^= (string_y[quo]<<rem)>>63;
            Self::ascon_permutation(&mut state, SB);
        }
        state[0] ^= (string_y[1]<<63)>>63;
        Self::ascon_permutation(&mut state, SK);
        // squeeze
        state[0..z/8].to_vec()
    }
    pub fn encrypt(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = vec![0;plaintext.len()];
        let mut state: [u64;5] = [0;5];
        let new_key: [u64;3] = self.re_key(true, &self.nonce).try_into().unwrap();
        for i in 0..3 {
            state[i] = new_key[i];
        }
        for i in 0..2 {
            state[3+i] = self.nonce[i];
        }
        for i in 0..(plaintext.len()/8) {
            Self::ascon_permutation(&mut state, SE);
            let u8_state_chunk = state[0].to_be_bytes();
            for j in 0..8 {
                ciphertext[i*8+j] = u8_state_chunk[j] ^ plaintext[i*8+j];
            }
        }
        if plaintext.len()%8 >0 {
            let rem = plaintext.len()%8;
            let quo = plaintext.len()/8;
            Self::ascon_permutation(&mut state, SE);
            let u8_state_chunk = state[0].to_be_bytes();
            for j in 0..rem {
                ciphertext[(quo*8)+j] = u8_state_chunk[j] ^ plaintext[(quo*8)+j];
            }
        }
        ciphertext
    }
    pub fn mac(&self, ad: &Vec<u8>, ct: &Vec<u8>) -> [u64;2] {
        // init
        let mut state: [u64;5] = [0;5];
        let iv_a: [u64; 3] = [0x018040010c01060c, 0, 0];
        for i in 0..2 {
            state[i] = self.nonce[i];
        }
        for i in 0..3 {
            state[2+i] = iv_a[i];
        }
        Self::ascon_permutation(&mut state, SH);
        // absorb associated data
        for i in 0..ad.len()/8 {
            state[0] ^= u64::from_be_bytes(ad[i*8..i*8+8].try_into().unwrap());
            Self::ascon_permutation(&mut state, SH);
        }
        if ad.len()%8 >0 {
            let rem = ad.len()%8;
            let quo = ad.len()/8;
            for i in 0..rem {
                state[0] ^= (ad[quo*8+i] as u64) << i*8 ;
            }
            Self::ascon_permutation(&mut state, SH);
        }
        state[4] ^= 1;
        // absorb ciphertext
        for i in 0..ct.len()/8 {
            state[0] ^= u64::from_be_bytes(ct[i*8..i*8+8].try_into().unwrap());
            Self::ascon_permutation(&mut state, SH);
        }
        if ct.len()%8 >0 {
            let rem = ct.len()%8;
            let quo = ct.len()/8;
            for i in 0..rem {
                state[0] ^= (ct[quo*8+i] as u64) << i*8 ;
            }
            Self::ascon_permutation(&mut state, SH);
        }
        // squeezing tag
        let new_key: [u64;2] = self.re_key(false, &state[0..2].try_into().unwrap()).try_into().unwrap();
        state[0] = new_key[0];
        state[1] = new_key[1];
        Self::ascon_permutation(&mut state, SH);
        state[0..2].try_into().unwrap() // tag
    }
}

pub fn verify(key: [u8;16], nonce: [u8;16], plaintext: &Vec<u8>, associated_data: &Vec<u8>, _ciphertext: &Vec<u8>) -> bool{
    // isap encryption
    let encryptor = IsapAead::new(key, nonce);
    let ciphertext = encryptor.encrypt(&plaintext);
    let tag = encryptor.mac(&associated_data, &ciphertext);
    // isap decryption
    let decryptor = IsapAead::new(key, nonce);
    let new_tag = decryptor.mac(&associated_data, &ciphertext);
    let mut new_message: Vec<u8> = vec![];
    if tag == new_tag {
        new_message = decryptor.encrypt(&ciphertext);
    }
    //println!("new message is {:0x?} ", new_message);
    assert_eq!(plaintext, &new_message);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn it_works() {
        let key = [3u8;16];
        let nonce = [5u8;16];
        let mut plaintext = vec![9u8;18];
        let mut associated_data = vec![15u8;20];
        let mut ciphertext: Vec<u8>;
        let tag: [u64;2];
        //println!("plaintext is {:0x?} ", plaintext);
        let start = Instant::now();
        // isap aead enc
        let encryptor = IsapAead::new(key, nonce);
        ciphertext = encryptor.encrypt(&mut plaintext);
        tag = encryptor.mac(&mut associated_data, &mut ciphertext);
        //println!("ciphertext is {:0x?} ", ciphertext);
        //println!("tag is {:0x?} ", tag);
        // isap aead dec
        let decryptor = IsapAead::new(key, nonce);
        let new_tag = decryptor.mac(&mut associated_data, &mut ciphertext);
        let mut new_message: Vec<u8> = vec![];
        //println!("new tag is {:0x?} ", new_tag);
        if tag == new_tag {
            new_message = decryptor.encrypt(&mut ciphertext);
        }
        //println!("new message is {:0x?} ", new_message);
        assert_eq!(plaintext, new_message);
        let elapsed = start.elapsed();
        println!("elapsed time {:?} ", elapsed);
    }
}
