
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
    rk: [u8;32],
    cks: Option<[u8;32]>, // sending chain key
    ckr: Option<[u8;32]>, // receiving chain key
    ns: usize, // sending message numbering
    nr: usize, // receiving message numbering
    pn: usize, // skipped messages from previous sending chain

    mk_skipped : HashMap<(Vec<u8>, usize), [u8; 32]>,

}

impl state {



    pub fn init_r(sk: [u8; 32], bob_dh_public_key: PublicKey) -> Self {
        let alice_priv : StaticSecret  = StaticSecret::new(OsRng);
        let alice_pub = PublicKey::from(&alice_priv);

        let (rk, cks) = kdf_rk(alice_priv.diffie_hellman(&bob_dh_public_key),
        &sk);
        state {
            is_r : true, 
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
    pub fn init_i(sk: [u8; 32]) -> (Self, PublicKey) {
        let bob_priv : StaticSecret  = StaticSecret::new(OsRng);
        let bob_pub = PublicKey::from(&bob_priv);

        
        let state = state {
            is_r : false,
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
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Option<(Header,Vec<u8>)> {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(self.dhs_pub, self.pn, self.ns);
        self.ns += 1;


        let encrypted_data = encrypt(&mk[..16], &CONSTANT_NONCE, plaintext, &serialize_header(&header, &ad)); // concat
        Some((header, encrypted_data)) // leaving out nonce, since it is a constant, as described bysignal docs
    }


    fn skip_message_keys(&mut self, until: usize) -> Result<(), &str> {
        if self.nr + MAX_SKIP < until {
            return Err("Skipped to many keys");
        }
        match self.ckr {
            Some(d) => {
                while self.nr  < until {
                    let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                    self.ckr = Some(ckr);
                    self.mk_skipped.insert((self.dhr_pub.unwrap().as_bytes().to_vec(), self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            },
            None => { Err("No Ckr set") }
        }
    }

    fn try_skipped_message_keys(&mut self, header: &Header, ciphertext: &[u8], nonce: &[u8; 13], ad: &[u8]) -> Option<Vec<u8>> {
        if self.mk_skipped.contains_key(&(header.ex_public_key_bytes(), header.n)) {
            let mk = *self.mk_skipped.get(&(header.ex_public_key_bytes(), header.n))
                .unwrap();
            self.mk_skipped.remove(&(header.ex_public_key_bytes(), header.n)).unwrap();
            Some(decrypt(&mk[..16], ciphertext, &serialize_header(&header, &ad), nonce))
        } else {
            None
        }
    }

    pub fn ratchet_decrypt_i(&mut self, header: &Header, ciphertext: &[u8],  ad: &[u8]) -> Vec<u8> {


        let plaintext = self.try_skipped_message_keys(header, ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {
                if Some(header.public_key) != self.dhr_pub{
                    if self.ckr != None {
                        self.skip_message_keys(header.pn).unwrap();
                    }
                    self.dhratchet_i(header);
                    
                }
                self.skip_message_keys(header.n).unwrap();
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                
                self.ckr = Some(ckr);
                self.nr += 1;

                
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, ciphertext, &serialize_header(&header, &ad));

                out
            }
        }
    }
    pub fn ratchet_decrypt_r(&mut self, header: &Header, ciphertext: &[u8],  ad: &[u8]) -> Vec<u8> {
        let plaintext = self.try_skipped_message_keys(header, ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {
                if Some(header.public_key) != self.dhr_pub{
                    if self.ckr != None {
                        self.skip_message_keys(header.pn).unwrap();
                    }
                    self.dhratchet_r(header);
                }
                self.skip_message_keys(header.n).unwrap();
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                self.ckr = Some(ckr);
                self.nr += 1;

                
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, ciphertext, &serialize_header(&header, &ad));
                out
            }
        }
    }
    fn dhratchet_r(&mut self, header: &Header) {
        println!("ratch r");
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // receiving new incoming public key
        self.dhr_pub = Some(header.public_key);
        
        let (rk, ckr) = kdf_rk(self.dhs_priv.diffie_hellman(&self.dhr_pub.unwrap()),
                               &self.rk);
        self.rk = rk;
        self.ckr = Some(ckr);

        // making own DH ratchet, and updating sending key chain
        self.dhs_priv = StaticSecret::new(OsRng);
        self.dhs_pub = PublicKey::from(&self.dhs_priv);
        let (rk, cks) = kdf_rk(self.dhs_priv.diffie_hellman(&self.dhr_pub.unwrap()),
         &self.rk);
        self.rk = rk;
        self.cks = Some(cks);
        
    }
    fn dhratchet_i(&mut self, header: &Header) {
        println!("ratch i");
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // receiving new incoming public key
        self.dhr_pub = Some(header.public_key);
        let (rk, ckr) = kdf_rk(self.dhs_priv.diffie_hellman(&self.dhr_pub.unwrap()),
                               &self.rk);
        self.rk = rk;
        
        self.ckr = Some(ckr);
        // making own DH ratchet, and updating sending key chain
        self.dhs_priv = StaticSecret::new(OsRng);
        self.dhs_pub = PublicKey::from(&self.dhs_priv);
        let (rk, cks) = kdf_rk(self.dhs_priv.diffie_hellman(&self.dhr_pub.unwrap()),
        &self.rk);

        self.rk = rk;
        
        self.cks = Some(cks);
        
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
