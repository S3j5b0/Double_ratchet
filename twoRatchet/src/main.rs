use x25519_dalek_ng::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};

use twoRatchet::ratchfuncs::{state};

fn main() {
    //// TODO:
    /// include ciphertext in header
    /// make error handling for aead decrpyiton
    // handshake is finished, sk is the finished output that the two parties share
    let sk = [16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29, 68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207];
    let ad_r = &[1];
    let ad_i = &[2];
    let r_priv : StaticSecret  = StaticSecret::new(OsRng);
    let r_pub = PublicKey::from(&r_priv);

    let i_priv : StaticSecret  = StaticSecret::new(OsRng);
    let i_pub = PublicKey::from(&i_priv);
    // initiator goes first, initializes with the sk, and generates a keypair

    let mut i_ratchet  = state::init_i(sk,i_priv,i_pub,&r_pub.as_bytes().to_vec());

    // now, I sends a payload with a public key in it to r, who can then initialize with i's pk and sk

    let mut r_ratchet = state::init_r(sk, r_priv,r_pub, &i_pub.as_bytes().to_vec());

    

    let (header_i_lost, enclost) = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i).unwrap();
    let declost = r_ratchet.ratchet_decrypt_r(&header_i_lost, &enclost, ad_i);

    
for _ in 1..5 {
    let (header_i, enc0) = i_ratchet.ratchet_encrypt(&b"bonkas".to_vec(), ad_i).unwrap();


    let dec0 = r_ratchet.ratchet_decrypt_r(&header_i,&enc0,ad_i);

    assert_eq!(dec0, b"bonkas".to_vec());

    let (header_r, enc_r) = r_ratchet.ratchet_encrypt(&b"downlink".to_vec(), ad_r).unwrap();

    let deci = i_ratchet.ratchet_decrypt_i(&header_r, &enc_r,ad_r);

    assert_eq!(deci, b"downlink".to_vec());
}
let (header_r, enc_l) = r_ratchet.ratchet_encrypt(&b"error".to_vec(), ad_r).unwrap();

//let header_r = &[1,2,3,23,32].to_vec();

let deci = i_ratchet.ratchet_decrypt_i(&header_r, &enc_l,ad_r);




let new_pk = r_ratchet.initiate_ratch_r();

// i receives 

let i_pk = i_ratchet.ratchet_decrypt_i(&new_pk, &[0], ad_r);


let _ = r_ratchet.ratchet_decrypt_r(&i_pk, &[0], ad_i);


let (header_r, enc_r) = r_ratchet.ratchet_encrypt(&b"newhcain".to_vec(), ad_r).unwrap();

let dec = i_ratchet.ratchet_decrypt_i(&header_r, &enc_r,ad_r);

assert_eq!(b"newhcain".to_vec(), dec);

// now r will send this pk to I


    



    
/*
   




*/

    // i encrypts something

 
    






    /*
    let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
    let alice_pub = PublicKey::from(&alice_priv);

    
    



    let bob_priv : StaticSecret  = StaticSecret::new(OsRng);
    let bob_pub = PublicKey::from(&bob_priv);


    let alice_DH_0_=  alice_priv.diffie_hellman(&bob_pub);


    let bob_DH_0 =  bob_priv.diffie_hellman(&alice_pub);


    let rk : [u8;32] = [82, 233, 86, 68, 105, 127, 137, 40, 235, 132, 64, 239, 132, 180, 52, 191, 55, 16, 253, 220, 86, 48, 67, 131, 224, 215, 186, 129, 195, 200, 194, 133];


*/
}