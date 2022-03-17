use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    consts::{U13, U8},
    Ccm,
};

pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Vec<u8> {
   /* println!("=========================================");
    println!("enc mk: {:?}", key);
    println!("nonce: {:?}", nonce);
    println!("ad: {:?}", ad);*/

    // Initialize CCM mode
  
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));

    // Encrypt and place ciphertext & tag in dst_out_ct
    let dst_out_ct = ccm.encrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: plaintext,
        },
    ).expect("failed to encrypt");

   // println!("ciperhtet: {:?}", dst_out_ct);
    dst_out_ct
}

/// Decrypts and verifies with AES-CCM-16-64-128.
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Option<Vec<u8>> {

    // Initialize CCM mode
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));
    // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
    let dst_out_pt = ccm.decrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: ciphertext,
        },
    ).unwrap_or([44].to_vec());

    if dst_out_pt != [44].to_vec() {
   
    Some(dst_out_pt)
}
    else{
    None
    }
}