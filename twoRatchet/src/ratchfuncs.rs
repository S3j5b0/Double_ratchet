
use x25519_dalek_ng::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use generic_array::{typenum::U32, GenericArray};
use std::collections::HashMap;
use sha2::Sha256;
use rand_core::{OsRng,};
use super::{
    encryption::{encrypt,decrypt},
    serializer::{serialize_header, deserialize_header}
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];
pub const MAX_SKIP: usize = 200;
pub struct state {
    is_r : bool,
    dhs_priv: StaticSecret,
    dhs_pub: PublicKey,

    dhr_pub: Option<PublicKey>,
    pub rk: [u8;32],
    cks: Option<[u8;32]>, // sending chain key
    ckr: Option<[u8;32]>, // receiving chain key
    ns: usize, // sending message numbering
    nr: usize, // receiving message numbering
    pn: usize, // skipped messages from previous sending chain

    mk_skipped : HashMap<(Vec<u8>, usize), [u8; 32]>,

}

impl state {



    pub fn init_r(sk: [u8; 32], i_dh_public_key: PublicKey) -> Self {
        let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
        let alice_pub = PublicKey::from(&alice_priv);

        let (rk, cks) = kdf_rk(alice_priv.diffie_hellman(&i_dh_public_key),
        &sk);
        println!("rinit rk {:?}", rk);
        state {
            is_r : true, 
            dhs_priv : alice_priv,
            dhs_pub : alice_pub,
            dhr_pub: Some(i_dh_public_key),

            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
        }
    }

    /// Init Ratchet without other [PublicKey]. Initialized first. Returns [Ratchet] and [PublicKey].
    pub fn init_i(sk: [u8; 32], r_dh_public_key: PublicKey) -> Self {
        let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
        let alice_pub = PublicKey::from(&alice_priv);

        let (rk, cks) = kdf_rk(alice_priv.diffie_hellman(&r_dh_public_key),
        &sk);
        println!("rinit rk {:?}", rk);
        state {
            is_r : true, 
            dhs_priv : alice_priv,
            dhs_pub : alice_pub,
            dhr_pub: Some(r_dh_public_key),

            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
        }
    }



 

}


fn kdf_rk(salt: SharedSecret,  input: &[u8]) -> ([u8;32],[u8;32]) {
    let mut output = [0u8; 64];
    let salt = salt.as_bytes();


    let h = Hkdf::<Sha256>::new(Some(salt),input);


    let info = b"Whispertext";

    h.expand(info, &mut output).unwrap();

    let (rk,ck) = output.split_at(32);

    (rk.try_into().unwrap(),ck.try_into().unwrap())
}

 fn kdf_ck(input: &[u8]) -> ([u8;32],[u8;32]) {
    let mut output = [0u8; 64];
    // kdf_ck should have a constant 
    let salt = &[1;32];


    let h = Hkdf::<Sha256>::new(Some(salt),input);


    let info = b"Whispertext";

    h.expand(info, &mut output).unwrap();

    let (rk,ck) = output.split_at(32);

    (rk.try_into().unwrap(),ck.try_into().unwrap())
}

pub struct Header {
    pub public_key: PublicKey,
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
}

impl Header {


    pub fn new( pkey : PublicKey, pn :usize, n: usize) -> Self {
        Header {
            public_key:  pkey,
            pn: pn,
            n : n,
        }
    }
    pub fn ex_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

}

/*
#[cfg(test)]
mod tests {
    #[test]
     fn skipmessage() {
         use crate::ratchfuncs::state;
        let sk = [16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29, 68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207];
        // initiator goes first, initializes with the sk, and generates a keypair

        let (mut i_ratchet, i_pk)  = state::init_i(sk,100);
        // now, I sends a payload with a public key in it to r, who can then initialize with i's pk and sk

        let mut r_ratchet = state::init_r(sk, i_pk,100);

         // r build some associated data,


         
        let ad = b"Associated data";
        let message1 = b"helloword";

        let (header1, enc0) = r_ratchet.ratchet_encrypt(&message1.to_vec(), ad).unwrap();

        // initiator is sent header and encrypted data
    
        let message1_dec = i_ratchet.ratchet_decrypt(&header1, &enc0, ad);
    
        // now that the first message has been decrypted, both parties are fully initalized
        // now i makes some messages taht will be lost
        for n in 1..4 {
            let (header2, encrypted2) = i_ratchet.ratchet_encrypt(&b"lostmessage".to_vec(), ad).unwrap();
        }    
        // and now I encrypts a message that actually will be decrypted a r

        let message2 = b"hacktheworld";
            // now i wants to encrypt something
        let (header3, encrypted3) = i_ratchet.ratchet_encrypt(&message2.to_vec(), ad).unwrap();
        let message2_dec = r_ratchet.ratchet_decrypt(&header3,&encrypted3,ad);
        assert_eq!(
            message2.to_vec(),
            message2_dec
        );
    }

}*/
