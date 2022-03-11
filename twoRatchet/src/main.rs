use x25519_dalek_ng::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};
use std::sync::mpsc;
use std::thread;
use hkdf::Hkdf;
use rand::{rngs::StdRng, Rng,SeedableRng};

use twoRatchet::ratchfuncs::state;
fn main() {

    // handshake is finished, sk is the finished output that the two parties share
    let mut r : StdRng = StdRng::from_entropy();
    let sk = r.gen::<[u8;32]>();

    // initiator goes first, initializes with the sk, and generates a keypair

    let (mut i_ratchet, i_pk)  = state::init_i(sk);

    // now, I sends a payload with a public key in it to r, who can then initialize with i's pk and sk

    let mut r_ratchet = state::init_r(sk, i_pk);

    // r build some associated data, it is yet to be determined exactly what to put here

    let ad = b"Associated data";
    let message1 = b"helloword";
    println!("responder message 1 {:?}", message1);
    //and encrypt an initial message
    let (header1, enc0) = r_ratchet.ratchet_encrypt(&message1.to_vec(), ad).unwrap();

    // initiator is sent header and encrypted data

    let message1_dec = i_ratchet.ratchet_decrypt(&header1, &enc0, ad);

    // now that the first message has been decrypted, both parties are fully initalized


    let message2 = b"hacktheworld";

    println!("msg2 {:?}", message2);

  //  println!("msg2 {:?}", message2);

    for n in 1..4 {
        let (header2, encrypted2) = i_ratchet.ratchet_encrypt(&b"lostmessage".to_vec(), ad).unwrap();
    }
    
    // now i wants to encrypt something
    let (header3, encrypted3) = i_ratchet.ratchet_encrypt(&message2.to_vec(), ad).unwrap();
    println!("_____________________________________________--");
    let message2_dec = r_ratchet.ratchet_decrypt(&header3,&encrypted3,ad);

    println!("msgdec'ed {:?}", message2_dec);

  //  println!("msg2dec {:?}", message2);











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