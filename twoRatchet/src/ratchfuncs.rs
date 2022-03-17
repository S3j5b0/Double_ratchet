
use x25519_dalek_ng::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use generic_array::{typenum::U32, GenericArray};
use std::collections::HashMap;
use sha2::Sha256;
use rand_core::{OsRng,};
use super::{
    encryption::{encrypt,decrypt},
    serializer::{serialize_header, deserialize_header,concat, serialize_pk,deserialize_pk,serialize_dhr,deserialize_dhr}
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];
pub const MAX_SKIP: usize = 200;
pub struct state {
    dhs_priv: StaticSecret,
    dhs_pub: PublicKey,
    dhr_pub: Option<PublicKey>,
    pub dh_id : usize,
    pub rk: [u8;32],
    pub cks: Option<[u8;32]>, // sending chain key
    pub ckr: Option<[u8;32]>, // receiving chain key
    ns: usize, // sending message numbering
    nr: usize, // receiving message numbering
    pn: usize, // skipped messages from previous sending chain
    mk_skipped : HashMap<(usize, usize), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,
    dhr_ack_nonce : u16,
    dhr_res_nonce : u16,


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
            dhr_ack_nonce : 0,
            dhr_res_nonce : 0,
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
            tmp_skey: None,
            dhr_ack_nonce: 0,
            dhr_res_nonce: 0,
        }
    }

    pub fn ratchet_i(&mut self, dhr_req:DhPayload) -> Vec<u8> {

        let r_dh_public_key = dhr_req.pk;

        let i_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let i_dh_public_key = PublicKey::from(&i_dh_privkey);

        let mut buf = [0; 32];
        buf.copy_from_slice(&r_dh_public_key[..32]);
        let r_dh_public_key = x25519_dalek_ng::PublicKey::from(buf);

        let r_dh_public_key = PublicKey::from(r_dh_public_key);
        let (rk, ckr) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key), &self.rk);
        let (rk, cks) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key),&rk);
        
        self.dhr_res_nonce = dhr_req.nonce;
        self.dhr_ack_nonce += self.dhr_ack_nonce;
        self.dhs_priv = i_dh_privkey;
        self.dhs_pub = i_dh_public_key;
        self.dhr_pub =  Some(r_dh_public_key);
        self.dh_id = self.dh_id +1;
        self.rk = rk;
        self.cks =  Some(cks);
        self.ckr =  Some(ckr);
        self.ns= 0;
        self.nr= 0;
        self.pn= 0;
        self.mk_skipped =  HashMap::new();

        // return the key

        let dhr_ack_payload = DhPayload {
            pk : i_dh_public_key.as_bytes().to_vec(),
            nonce :self.dhr_ack_nonce,
        };
        serialize_dhr(dhr_ack_payload)
        
    }

    pub fn ratchet_r(&mut self, dhr_ack:DhPayload)  {
        let i_dh_public_key = dhr_ack.pk;
        let r_dh_privkey : StaticSecret  = self.tmp_skey.clone().unwrap();
        let r_dh_public_key = self.tmp_pkey.unwrap();

        let mut buf = [0; 32];
        buf.copy_from_slice(&i_dh_public_key[..32]);
        let i_dh_public_key = x25519_dalek_ng::PublicKey::from(buf);

        let r_dh_public_key = PublicKey::from(r_dh_public_key);
        let (rk, cks) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key), &self.rk);
        let (rk, ckr) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key),&rk);


        self.dhr_ack_nonce = dhr_ack.nonce;
        self.dhr_res_nonce += self.dhr_res_nonce;
        self.dhs_priv = r_dh_privkey;
        self.dhs_pub = i_dh_public_key;
        self.dhr_pub =  Some(r_dh_public_key);
        self.dh_id = self.dh_id +1;
        self.rk = rk;
        self.cks =  Some(cks);
        self.ckr =  Some(ckr);
        self.ns= 0;
        self.nr= 0;
        self.pn= 0;
        self.mk_skipped =  HashMap::new();
        
    }

    pub fn initiate_ratch_r(&mut self)-> Vec<u8>{
        let r_priv : StaticSecret  = StaticSecret::new(OsRng);
        let r_pub = PublicKey::from(&r_priv);
        let dhrpayload = DhPayload {
            pk : r_pub.as_bytes().to_vec(),
            nonce: self.dhr_res_nonce,
        };
        let ser = serialize_dhr(dhrpayload);

        self.tmp_pkey = Some(r_pub);
        self.tmp_skey = Some(r_priv);
        self.dhr_res_nonce += 1;


        ser

    }

    /// Encrypt Plaintext with [Ratchet]. Returns Message [Header] and ciphertext.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
    

        let encrypted_data = encrypt(&mk[..16], &CONSTANT_NONCE, plaintext, &concat(self.dh_id, self.pn,self.ns, &ad)); // concat

        let header = Header::new( self.pn, self.ns,self.dh_id,encrypted_data.clone());
        self.ns += 1;
        serialize_header(&header) // leaving out nonce, since it is a constant, as described bysignal docs
    }


    pub fn ratchet_decrypt_r(&mut self, header: &Vec<u8>,  ad: &[u8]) -> Vec<u8> {
        let header = match deserialize_header(header) {
            Some(x) => x,
            None => {
                self.ratchet_r(deserialize_dhr(header));
                return [1,2,34].to_vec()},
    };
   // let ciphertext = header.ciphertext;
        let plaintext = self.try_skipped_message_keys(&header, &header.ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {

                self.skip_message_keys(header.n);
                
  
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                
                self.ckr = Some(ckr);
                self.nr += 1;
 
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, &header.ciphertext, &concat(header.dh_pub_id, header.pn,header.n, &ad));

                
                match out {
                    Some(x) => {
                        return x
                    },
                    None =>{ 
                        return [0].to_vec()
                    }};
            }
        }
    }
    pub fn ratchet_decrypt_i(&mut self, header: &Vec<u8>, ad: &[u8]) -> Vec<u8> {

        let header = match deserialize_header(header) {
            Some(x) => x,
            None => {
                let outkey = self.ratchet_i(deserialize_dhr(header));
                return outkey},
        };
        let plaintext = self.try_skipped_message_keys(&header, &header.ciphertext, &CONSTANT_NONCE, ad);
        match plaintext {
            Some(d) => d,
            None => {
 
                self.skip_message_keys(header.n);
                
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                
                self.ckr = Some(ckr);
                self.nr += 1;

                
                let out = decrypt(&mk[..16],&CONSTANT_NONCE, &header.ciphertext, &concat(header.dh_pub_id, header.pn,header.n, &ad));

                match out {
                    Some(x) => {
                        return x
                    },
                    None =>{ 
                        return [0].to_vec()
                    }};
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
        if self.mk_skipped.contains_key(&(header.dh_pub_id, header.n)) {
            let mk = *self.mk_skipped.get(&(header.dh_pub_id, header.n))
                .unwrap();
            self.mk_skipped.remove(&(header.dh_pub_id, header.n)).unwrap();
            decrypt(&mk[..16], nonce,ciphertext, &concat(header.dh_pub_id, header.pn,header.n, &ad))
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
    pub dh_pub_id:usize,
    pub ciphertext : Vec<u8>,
}

impl Header {


    pub fn new( pn :usize, n: usize, dh_pub_id: usize, cipher: Vec<u8>) -> Self {
        Header {
            pn: pn,
            n : n,
            dh_pub_id: dh_pub_id,
            ciphertext: cipher,
        }
    }


}

pub struct DhPayload {
    pub pk: Vec<u8>, // public key that is sent
    pub nonce : u16, // DHRAckNonce, or DHRResNonce
}
impl DhPayload {


    pub fn new( pk : Vec<u8>, nonce : u16) -> Self {
        DhPayload {
            pk: pk,
            nonce: nonce,
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
