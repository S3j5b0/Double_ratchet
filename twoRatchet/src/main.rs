use x25519_dalek::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};
use std::sync::mpsc;
use std::thread;
use hkdf::Hkdf;
use twoRatchet::ratchfuncs;
fn main() {



    let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
    let alice_pub = PublicKey::from(&alice_priv);

    
    



    let bob_priv : StaticSecret  = StaticSecret::new(OsRng);
    let bob_pub = PublicKey::from(&bob_priv);


    let alice_DH_0_=  alice_priv.diffie_hellman(&bob_pub);


    let bob_DH_0 =  bob_priv.diffie_hellman(&alice_pub);


    let rk : [u8;32] = [82, 233, 86, 68, 105, 127, 137, 40, 235, 132, 64, 239, 132, 180, 52, 191, 55, 16, 253, 220, 86, 48, 67, 131, 224, 215, 186, 129, 195, 200, 194, 133];



}