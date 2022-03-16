
use x25519_dalek_ng::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use generic_array::{typenum::U32, GenericArray};
use std::collections::HashMap;
use sha2::Sha256;
use rand_core::{OsRng,};
use super::{
    encryption::{encrypt,decrypt},
    serializer::{serialize_header, deserialize_header,concat, serialize_pk,deserialize_pk}
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];
pub const MAX_SKIP: usize = 200;
pub struct state {
    is_r : bool,
    dhs_priv: StaticSecret,
    dhs_pub: PublicKey,
    dhr_pub: Option<PublicKey>,
    dh_id : usize,
    pub rk: [u8;32],
    cks: Option<[u8;32]>, // sending chain key
    ckr: Option<[u8;32]>, // receiving chain key
    ns: usize, // sending message numbering
    nr: usize, // receiving message numbering
    pn: usize, // skipped messages from previous sending chain

    mk_skipped : HashMap<(usize, usize), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,


}

impl state {



    pub fn init_r(sk: [u8; 32],  r_dh_privkey: StaticSecret,r_dh_public_key :PublicKey,i_dh_public_key: &[u8]) -> Self {
        let mut buf = [0; 32];
        buf.copy_from_slice(&i_dh_public_key[..32]);
        let i_dh_public_key = x25519_dalek_ng::PublicKey::from(buf);

        let (rk, cks) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key),
        &sk);
        let (rk, ckr) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key),
        &rk);
        state {
            is_r : true, 
            dhs_priv : r_dh_privkey,
            dhs_pub : r_dh_public_key,
            dhr_pub: Some(i_dh_public_key),
            dh_id : 0,
            rk,
            cks: Some(cks),
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
            tmp_pkey: None,
            tmp_skey:None,
        }
    }

    /// Init Ratchet without other [PublicKey]. Initialized first. Returns [Ratchet] and [PublicKey].
    pub fn init_i(sk: [u8; 32], i_dh_privkey: StaticSecret,i_dh_public_key :PublicKey,r_dh_public_key:&[u8]) -> Self {


        let mut x_i_bytes = [0; 32];
        x_i_bytes.copy_from_slice(&r_dh_public_key[..32]);
        let r_dh_public_key = x25519_dalek_ng::PublicKey::from(x_i_bytes);


        let r_dh_public_key = PublicKey::from(r_dh_public_key);
        let (rk, ckr) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key),
        &sk);
        let (rk, cks) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key),
        &rk);
        state {
            is_r : true, 
            dhs_priv : i_dh_privkey,
            dhs_pub : i_dh_public_key,
            dhr_pub: Some(r_dh_public_key),
            dh_id : 0,
            rk,
            cks: Some(cks),
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
            tmp_pkey: None,
            tmp_skey: None
        }
    }

    pub fn initiate_ratch_r(&mut self)-> Vec<u8>{
        let r_priv : StaticSecret  = StaticSecret::new(OsRng);
        let r_pub = PublicKey::from(&r_priv);
        let ser = serialize_pk(&r_pub.as_bytes().to_vec());

        self.tmp_pkey = Some(r_pub);
        self.tmp_skey = Some(r_priv);


        r_pub.as_bytes().to_vec()

    }

    /// Encrypt Plaintext with [Ratchet]. Returns Message [Header] and ciphertext.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Option<(Vec<u8>,Vec<u8>)> {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new( self.pn, self.ns,self.dh_id);
        self.ns += 1;

        let encrypted_data = encrypt(&mk[..16], &CONSTANT_NONCE, plaintext, &concat(&header, &ad)); // concat

 
        Some((serialize_header(&header), encrypted_data)) // leaving out nonce, since it is a constant, as described bysignal docs
    }


    pub fn ratchet_decrypt_r(&mut self, header: &Vec<u8>, ciphertext: &[u8],  ad: &[u8]) -> Vec<u8> {
        let header = match deserialize_header(header) {
            Some(x) => x,
            None => return [1,2,34].to_vec(),
        };

        let plaintext = self.try_skipped_message_keys(&header, ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {

                self.skip_message_keys(header.n - self.nr);
                
  
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                
                self.ckr = Some(ckr);
                self.nr += 1;

                
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, ciphertext, &concat(&header, &ad));

                out
            }
        }
    }
    pub fn ratchet_decrypt_i(&mut self, header: &Vec<u8>, ciphertext: &[u8],  ad: &[u8]) -> Vec<u8> {

        let header = match deserialize_header(header) {
            Some(x) => x,
            None => return [1,2,34].to_vec(),
        };
        let plaintext = self.try_skipped_message_keys(&header, ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {
 
                self.skip_message_keys(header.n - self.nr);
                
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                
                self.ckr = Some(ckr);
                self.nr += 1;

                
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, ciphertext, &concat(&header, &ad));

                out
            }
        }
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
                    self.mk_skipped.insert((self.dh_id, self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            },
            None => { Err("No Ckr set") }
        }
    }

    fn try_skipped_message_keys(&mut self, header: &Header, ciphertext: &[u8], nonce: &[u8; 13], ad: &[u8]) -> Option<Vec<u8>> {
        if self.mk_skipped.contains_key(&(header.DH_pub_id, header.n)) {
            let mk = *self.mk_skipped.get(&(header.DH_pub_id, header.n))
                .unwrap();
            self.mk_skipped.remove(&(header.DH_pub_id, header.n)).unwrap();
            Some(decrypt(&mk[..16], nonce,ciphertext, &concat(&header, &ad)))
        } else {
            None
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
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
    pub DH_pub_id:usize,
}

impl Header {


    pub fn new( pn :usize, n: usize, DH_pub_id: usize) -> Self {
        Header {
            pn: pn,
            n : n,
            DH_pub_id: DH_pub_id,
        }
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
