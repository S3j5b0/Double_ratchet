use x25519_dalek_ng::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};
use std::sync::mpsc;
use std::thread;
use hkdf::Hkdf;
use rand::{rngs::StdRng, Rng,SeedableRng};

use twoRatchet::ratchfuncs::state;
fn main() {

    // handshake is finished, sk is the finished output that the two parties share
    let sk = [16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29, 68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207];


    // initiator goes first, initializes with the sk, and generates a keypair

    let (mut i_ratchet, i_pk)  = state::init_i(sk);

    // now, I sends a payload with a public key in it to r, who can then initialize with i's pk and sk

    let mut r_ratchet = state::init_r(sk, i_pk);


    let message1 = b"Hello World".to_vec();                               // Data to be encrypted
    let ad = b"Associated Data";      

    // r makes an initial message that I can initialize with

    let (header_r, encinitial) = r_ratchet.ratchet_encrypt(&message1.to_vec(), ad).unwrap();

    let decrypted = i_ratchet.ratchet_decrypt_i(&header_r, &encinitial, ad);

    // sending random messaages

    // now we try to send a random message:
    let (header_i, enc1) = i_ratchet.ratchet_encrypt(&b"dojnks".to_vec(), ad).unwrap();
    let decrypted = r_ratchet.ratchet_decrypt_r(&header_i, &enc1, ad);
    println!("???????????????????????????");
    assert_eq!(decrypted, b"dojnks".to_vec());


    let (header_r, enc0) = r_ratchet.ratchet_encrypt(&b"dojnks".to_vec(), ad).unwrap();

    let decrypted = i_ratchet.ratchet_decrypt_i(&header_r, &enc0, ad);
    assert_eq!(decrypted, b"dojnks".to_vec());


    
    let (bong, bing) = i_ratchet.ratchet_encrypt(&b"bonkas".to_vec(), ad).unwrap();

    for n in 1..5 {

    let (header_i, enc1) = i_ratchet.ratchet_encrypt(&b"bonkas".to_vec(), ad).unwrap();

    let decrypted0 = r_ratchet.ratchet_decrypt_r(&header_i, &enc1, ad);
    assert_eq!(decrypted0, b"bonkas".to_vec());
    }

    
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