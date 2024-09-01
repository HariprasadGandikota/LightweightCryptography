const RH :usize = 64;
const RB :usize = 1;
const SH :usize = 12;
const SB :usize = 1;
const SE :usize = 6;
const SK :usize = 12;
const N :usize = 40;
const K :usize = 16;
// converts byte (u8) array into a u64 array.
fn bytes_to_u64(bytes_array: &[u8], u64_array: &mut [u64]) {
    let mut index: usize = 0;
    for i in 0..bytes_array.len()/8 {
        u64_array[i] = u64::from_le_bytes(bytes_array[index..(index+8)].try_into().unwrap());
        index += 8;
    }
}
// converts u64 array into a byte (u8) array.
fn u64_to_bytes(u64_array: &[u64], bytes_array: &mut [u8]) {
    for i in 0..u64_array.len() {
        let temp = u64_array[i].to_le_bytes();
        for j in 0..8 {
            bytes_array[i*8 + j] = temp[j];
        }
    }
}
// access a bit value from a byte (u8) array. pass the index of the bit.
// return u8 integer with the required bit set to msb
fn access_bit_from_array(arr: &[u8], round: usize) -> u8 {
    (arr[arr.len()-1 - round/8] >> round%8) << 7
}
// fills the byte (u8) array with specified no. of bytes (0's).
fn insert_extra_bytes(arr: &mut Vec<u8>, extra_bytes: usize) {
    for i in 0..extra_bytes {
        if i == 0 {
            arr.insert(0, 1);
        }
        else {
            arr.insert(0, 0);
        }
    }
}
// removes specified no. of bytes from the byte (u8) array.
fn remove_extra_bytes(arr: &mut Vec<u8>, extra_bytes: usize) {
    for _ in 0..extra_bytes {
        arr.remove(0);
    }
}

pub struct IsapAead {
    key: [u8;16],
    nonce: [u8;16],
}

impl IsapAead {
    pub fn new(key: [u8;16], nonce: [u8;16]) -> Self {
        Self { key, nonce}
    }
    // performs 320-bit ascon permutation on the state byte (u8) array.
    // pass no. of rounds to the function along with mutable reference of state.
    pub fn ascon_permutation(state: &mut [u8], rounds: usize){
        let mut u64_state: [u64; 5] = [0;5];
        bytes_to_u64(state, &mut u64_state);
        for i in 0..rounds {
            Self::constant_add(&mut u64_state, i, rounds);
            Self::substitution(&mut u64_state);
            Self::linear_diffusion(&mut u64_state);
        }
        u64_to_bytes(&u64_state, state);
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
            state[i] ^= (state[i].rotate_right(rotate_index[i][0])) ^ (state[i].rotate_right(rotate_index[i][1]));
        }
    }
    // pass a mutable reference to a plaintext byte (u8) vector to encrypt.
    pub fn encrypt(&self, plaintext: &mut Vec<u8>) -> Vec<u8> {
        // initialization phase
        let mut ciphertext: Vec<u8> = vec![];
        let extra_bytes = 8- (plaintext.len()*8 % RH)/8;
        insert_extra_bytes(plaintext, extra_bytes);
        let enc_key: Vec<u8> = self.isap_re_key(true, &self.nonce);
        let mut state: [u8;40] = [0;40];
        for i in 0..N-K {
            state[i] = enc_key[i];
        }
        for i in 0..K {
            state[N-K+i] = self.nonce[i];
        }
        // squeeze phase
        for i in 0..plaintext.len()*8/RH {
            Self::ascon_permutation(&mut state, SE);
            for j in 0..8 {
                ciphertext.push(state[j] ^ plaintext[i*8+j]);//-(plaintext.len()% RH/8)]);
            }
        }
        remove_extra_bytes(&mut ciphertext, extra_bytes);
        remove_extra_bytes(plaintext, extra_bytes);
        ciphertext
    }
    // performs isap rey-keying function with key, flag (enc/mac), string_y.
    fn isap_re_key(&self, enc: bool, string_y: &[u8]) -> Vec<u8> {
        let mut state = [0u8;40];
        let mut new_k: Vec<u8> = vec![];
        let z;
        let iv: Vec<u8>;
        let iv_ke: Vec<u8> = vec![0x03, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let iv_ka: Vec<u8> = vec![0x02, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
        for i in 0..K {
            state[i] = self.key[i];
        }
        for i in 0..iv.len() {
            state[K+i] = iv[i];
        }
        Self::ascon_permutation(&mut state, SK);
        // absorb phase
        for i in 0..(string_y.len()*8/RB)-1 {
            state[0] ^= access_bit_from_array(string_y, i);
            Self::ascon_permutation(&mut state, SB);
        }
        state[0] ^= access_bit_from_array(string_y, K-1);
        Self::ascon_permutation(&mut state, SK);
        //squeeze phase
        for i in 0..z {
            new_k.push(state[i]);
        }
        new_k
    }
    // pass mutable references for associated_data, ciphertext to generate tag.
    pub fn isap_mac(&self, associated_data: &mut Vec<u8>, ciphertext: &mut Vec<u8>) -> Vec<u8> {
        // initialization 
        // break ad and ciphertext into rh bit blocks and fill with 0's <<<<<
        let mut tag: Vec<u8> = vec![0;16];
        let ad_extra_bytes = associated_data.len() % RH/8;
        insert_extra_bytes(associated_data, ad_extra_bytes);
        let ct_extra_bytes = ciphertext.len() % RH/8;
        insert_extra_bytes(ciphertext, ct_extra_bytes);
        let mut state = [0u8;40];
        let iv_a: [u8; 24] = [0x03, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for i in 0..K {
            state[i] = self.nonce[i];
        }
        for i in 0..iv_a.len() {
            state[K+i] = iv_a[i];
        }
        Self::ascon_permutation(&mut state, SH);
        // absorbing associated data
        for i in 0..associated_data.len()*8/RH {
            for j in 0..8 {
                state[j] ^= associated_data[i*8+j];
            }
            Self::ascon_permutation(&mut state, SH);
        }
        state[N-1] ^= 1;
        // absorbing cipher text
        for i in 0..ciphertext.len()*8/RH {
            for j in 0..8 {
                state[j] ^= ciphertext[i*8+j];
            }
            Self::ascon_permutation(&mut state, SH);
        }
        // squeezing
        let new_k: Vec<u8> = self.isap_re_key(false, &state[0..K]);
        for i in 0..K {
            state[i] = new_k[i];
        }
        Self::ascon_permutation(&mut state, SH);
        for i in 0..K {
            tag[i] = state[i];
        }
        remove_extra_bytes(associated_data, ad_extra_bytes);
        remove_extra_bytes(ciphertext, ct_extra_bytes);
        tag
    }
}

pub fn verify(key: [u8;16], nonce: [u8;16], plaintext: &mut Vec<u8>, associated_data: &mut Vec<u8>, _ciphertext: &mut Vec<u8>) -> bool{
        /*print!("plaintext is: ");
        for i in 0..plaintext.len() {
            print!("{} ", plaintext[i]);
        }
        println!();*/
        // isap aead enc
        let encryptor = IsapAead::new(key, nonce);
        let mut new_ct = encryptor.encrypt(plaintext);
        let tag = encryptor.isap_mac(associated_data, &mut new_ct);
        //assert_eq!(ciphertext, &mut new_ct);
        /*print!("ciphertext is: ");
        for i in 0..ciphertext.len() {
            print!("{} ", ciphertext[i]);
        }
        println!();
        print!("tag is: ");
        for i in 0..tag.len() {
            print!("{} ", tag[i]);
        }
        println!();*/
        //println!("ciphertext ={:?} ", ciphertext);
        //println!("new_ct = {:?} ", new_ct);
        //println!("tag = {:?} ", tag);
        // isap aead dec
        let decryptor = IsapAead::new(key, nonce);
        let new_tag = decryptor.isap_mac(associated_data, &mut new_ct);
        let mut new_message: Vec<u8> = vec![];
        if tag == new_tag {
            new_message = decryptor.encrypt(&mut new_ct);
        }
        /*print!("new_message is: ");
        for i in 0..new_message.len() {
            print!("{} ", new_message[i]);
        }*/
        assert_eq!(plaintext, &mut new_message);
        true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let key = [3u8;16];
        let nonce = [5u8;16];
        let mut plaintext = vec![9u8;18];
        let mut associated_data = vec![15u8;20];
        let mut ciphertext: Vec<u8>;
        let tag: Vec<u8>;
        print!("plaintext is: ");
        for i in 0..plaintext.len() {
            print!("{} ", plaintext[i]);
        }
        println!();
        // isap aead enc
        let encryptor = IsapAead::new(key, nonce);
        ciphertext = encryptor.encrypt(&mut plaintext);
        tag = encryptor.isap_mac(&mut associated_data, &mut ciphertext);
        print!("ciphertext is: ");
        for i in 0..ciphertext.len() {
            print!("{} ", ciphertext[i]);
        }
        println!();
        print!("tag is: ");
        for i in 0..tag.len() {
            print!("{} ", tag[i]);
        }
        println!();
        // isap aead dec
        let decryptor = IsapAead::new(key, nonce);
        let new_tag = decryptor.isap_mac(&mut associated_data, &mut ciphertext);
        let mut new_message: Vec<u8> = vec![];
        if tag == new_tag {
            new_message = decryptor.encrypt(&mut ciphertext);
        }
        print!("new_message is: ");
        for i in 0..new_message.len() {
            print!("{} ", new_message[i]);
        }
        assert_eq!(plaintext, new_message);
    }
}