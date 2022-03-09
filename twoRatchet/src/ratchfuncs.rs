
use x25519_dalek::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use generic_array::{typenum::U32, GenericArray};
use std::collections::HashMap;
use sha2::Sha256;
use rand_core::{OsRng,};
use crate::encryption::{encrypt,decrypt};


pub struct Header {
    pub public_key: PublicKey,
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
}
pub struct state {
    dhs_priv: StaticSecret,
    dhs_pub: PublicKey,
    dhr_pub: Option<PublicKey>,
    rk: [u8;32],
    cks: Option<[u8;32]>, // sending chain key
    ckr: Option<[u8;32]>, // receiving chain key
    ns: usize, // sending message numbering
    nr: usize, // receiving message numbering
    pn: usize, // skipped messages from previous sending chain
    mk_skipped : HashMap<(Vec<u8>, usize), [u8; 32]>,

}

impl state {



    pub fn init_alice(sk: [u8; 32], bob_dh_public_key: PublicKey) -> Self {
        let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
        let alice_pub = PublicKey::from(&alice_priv);

        let (rk, cks) = kdf_rk(alice_priv.diffie_hellman(&bob_dh_public_key),
        &sk);
        state {
            dhs_priv : alice_priv,
            dhs_pub : alice_pub,
            dhr_pub: Some(bob_dh_public_key),
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
    pub fn init_bob(sk: [u8; 32]) -> (Self, PublicKey) {
        let bob_priv : StaticSecret  = StaticSecret::new(OsRng);
        let bob_pub = PublicKey::from(&bob_priv);

        
        let state = state {
            dhs_priv : bob_priv,
            dhs_pub: bob_pub,
            dhr_pub: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
        };
        (state,bob_pub)
    }

    /// Encrypt Plaintext with [Ratchet]. Returns Message [Header] and ciphertext.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (Header, Vec<u8>, [u8; 12]) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        self.ns += 1;
        let (encrypted_data, nonce) = encrypt(&mk, plaintext, &header.concat(ad));
        (header, encrypted_data, nonce)
    }



//pub fn dh_ratchet()


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

