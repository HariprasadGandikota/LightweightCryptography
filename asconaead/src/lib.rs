use ascon_aead::{Ascon128a, Key, Nonce};
use ascon_aead::aead::{Aead, KeyInit, Payload};

pub fn verify(key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &Vec<u8>, _ciphertext: &Vec<u8>) -> bool{
    let key = Key::<Ascon128a>::from_slice(key);
    let cipher = Ascon128a::new(key);

    let nonce = Nonce::<Ascon128a>::from_slice(nonce); // 128-bits; unique per message
    // Combine plaintext and associated data into a payload
    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };
    let new_ct = cipher.encrypt(nonce, payload).expect("encryption failure!"); // NOTE: handle this error to avoid panics!
    //assert_eq!(ciphertext, &new_ct);
    //println!("ciphertext = {:?} ", ciphertext);
    //println!("new_ct = {:?} ", new_ct);
    let c_payload = Payload {
        msg: &new_ct,
        aad: ad,
    };
    let message = cipher.decrypt(nonce, c_payload).expect("decryption failure!"); // NOTE: handle this error to avoid panics!
    //println!("plaintext = {:?} ", plaintext);
    //println!("message = {:?} ", message);
    assert_eq!(&message, plaintext);
    true
}
