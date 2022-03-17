use x25519_dalek_ng::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};

use twoRatchet::ratchfuncs::{state};

fn main() {
    //// TODO:
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

    

    let header_i_lost = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);

    let header_r_lost = r_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_r);
    
for _ in 1..5 {
    let header_i = i_ratchet.ratchet_encrypt(&b"bonkas".to_vec(), ad_i);


    let dec0 = r_ratchet.ratchet_decrypt_r(&header_i,ad_i);

    assert_eq!(dec0, b"bonkas".to_vec());

    let header_r= r_ratchet.ratchet_encrypt(&b"downlink".to_vec(), ad_r);

    let deci = i_ratchet.ratchet_decrypt_i(&header_r,ad_r);

    assert_eq!(deci, b"downlink".to_vec());
}





let new_pk = r_ratchet.initiate_ratch_r();

// i receives this new key, and sends back 


let i_pk = i_ratchet.ratchet_decrypt_i(&new_pk, ad_r);

 // i sends this pk to r 


let declost = r_ratchet.ratchet_decrypt_r(&new_pk, ad_r);


/*

// now r will send this pk to I

*/
    



    
}