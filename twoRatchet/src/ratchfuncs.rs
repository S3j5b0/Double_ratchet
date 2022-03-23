
use x25519_dalek_ng::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use generic_array::{typenum::U32, GenericArray};
use std::collections::HashMap;
use sha2::Sha256;
use rand_core::{OsRng,};
use super::{
    encryption::{encrypt,decrypt},
    serializer::{concat,prepare_header,unpack_header}
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];
pub const MAX_SKIP: u16 = 200;
pub struct state {
    pub is_i : bool,
    dhs_priv: StaticSecret,
    dhs_pub: PublicKey,
    dhr_pub: Option<PublicKey>,
    pub rk: [u8;32],
    pub cks: Option<[u8;32]>, // sending chain key
    pub ckr: Option<[u8;32]>, // receiving chain key
    pub ns: u16, // sending message numbering
    nr: u16, // receiving message numbering
    pn: u16, // skipped messages from previous sending chain
    mk_skipped : HashMap<(u16, u16), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,
    dhr_ack_nonce : u8,
    dhr_res_nonce : u8,
    dh_id : u16,
    ad_i : Vec<u8>,
    ad_r : Vec<u8>


}

impl state {



    pub fn init_r(sk: [u8; 32], ckr: [u8; 32], sck: [u8; 32],  ad_i :Vec<u8>, ad_r:Vec<u8>) -> Self {


        let r_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let r_dh_public_key = PublicKey::from(&r_dh_privkey);
        state {
            is_i : false,
            dhs_priv : r_dh_privkey,
            dhs_pub : r_dh_public_key,
            dhr_pub: None,
            rk: sk,
            cks: Some(sck),
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
            tmp_pkey: None,
            tmp_skey: None,
            dhr_ack_nonce: 0,
            dhr_res_nonce: 0,
            dh_id: 0,
            ad_i,
            ad_r
        }
    }

    /// Init Ratchet without other [PublicKey]. Initialized first. Returns [Ratchet] and [PublicKey].
    pub fn init_i(sk: [u8; 32],  ckr: [u8; 32], sck: [u8; 32],ad_i :Vec<u8>,ad_r: Vec<u8>) -> Self {

        let i_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let i_dh_public_key = PublicKey::from(&i_dh_privkey);

        let first_dh_req = DhPayload{
            pk : i_dh_public_key.as_bytes().to_vec(),
            nonce : 1
        };

    

        let mut state  = state {
            is_i: true,
            dhs_priv : i_dh_privkey.clone(),
            dhs_pub : i_dh_public_key,
            dhr_pub: None,
            rk: sk,
            cks: Some(sck),
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
            tmp_pkey: Some(i_dh_public_key),
            tmp_skey: Some(i_dh_privkey),
            dhr_ack_nonce: 0,
            dhr_res_nonce: 0,
            dh_id: 0,
            ad_i,
            ad_r
        };

        state
    }
    pub fn i_initiate_ratch(&mut self) -> Vec<u8> {
        let i_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let i_dh_public_key = PublicKey::from(&i_dh_privkey);

        self.tmp_pkey = Some(i_dh_public_key);
        self.tmp_skey = Some(i_dh_privkey);
        let dh_req = DhPayload{
            pk : i_dh_public_key.as_bytes().to_vec(),
            nonce : self.dhr_res_nonce +1
        };

        let concat_dhr = concat_dhr(&i_dh_public_key.as_bytes().to_vec(), self.dhr_res_nonce+1);

        let enc = self.ratchet_encrypt(&concat_dhr, &self.ad_i.clone())[1..].to_vec();
        let mut encoded = [5].to_vec();
        encoded.extend(enc);
        encoded
    }
    pub fn ratchet_r(&mut self, dhr_encrypted:Vec<u8>) -> Option<Vec<u8>> {

        // first, attempt to decrypt incoming key
        let dhr_serial = match self.ratchet_decrypt(dhr_encrypted) {
                Some(x) => x,
                None => panic!("ahhrhrh"),
            
            
        };
        
        // first we deserialize dhr and create our own dhrackknowledgement message
        let dhr_req = split_dhr(dhr_serial);
        self.dhr_res_nonce = dhr_req.nonce;

        let mut buf = [0; 32];
        buf.copy_from_slice(&dhr_req.pk[..32]);
        let i_dh_public_key = PublicKey::from(buf);

        let r_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let r_dh_public_key = PublicKey::from(&r_dh_privkey);

        // create own drh ack nonce message
        
        self.dhr_ack_nonce += 1;

        let dhr_ack_payload = DhPayload {
            pk : r_dh_public_key.as_bytes().to_vec(),
            nonce :self.dhr_ack_nonce,
        };
        
        let concat_dhr = concat_dhr(&r_dh_public_key.as_bytes().to_vec(), self.dhr_ack_nonce);
        let dhr_ack = self.ratchet_encrypt(&concat_dhr, &self.ad_r.clone())[1..].to_vec();
            
        
        let mut encoded = [6].to_vec();
        encoded.extend(dhr_ack);

        // We then do the ratchet
        let (rk, ckr) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key), &self.rk);
        
        let (rk, cks) = kdf_rk(r_dh_privkey.diffie_hellman(&i_dh_public_key),&rk);

        self.dh_id += 1;
        self.dhs_priv = r_dh_privkey;
        self.dhs_pub = r_dh_public_key;
        self.dhr_pub =  Some(i_dh_public_key);
        self.rk = rk;
        self.cks =  Some(cks);
        self.ckr =  Some(ckr);
        self.pn= self.ns;
        self.ns= 0;
        self.nr= 0;
        
        self.mk_skipped =  HashMap::new();

        // return the key
        Some(encoded) 
        
    }

    pub fn ratchet_i(&mut self, dhr_ack_encrypted:Vec<u8>) -> bool {

        
        let dhr_ack_serial = match self.ratchet_decrypt(dhr_ack_encrypted){    
                Some(x) => x,
                None => return false,
            
        };
        
        let dhr_ack = split_dhr(dhr_ack_serial);

        // creating keys
        let mut buf = [0; 32];
        
        buf.copy_from_slice(&dhr_ack.pk[..32]);
        let r_dh_public_key = PublicKey::from(buf);


        // now that i has received an ack from r, she can use her temporary keys, and overwrite her old ones

        let i_dh_privkey = self.tmp_skey.clone().unwrap();
        let i_dh_public_key = self.tmp_pkey.unwrap();

        // We then do the ratchet


        let (rk, cks) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key), &self.rk);
        
        let (rk, ckr) = kdf_rk(i_dh_privkey.diffie_hellman(&r_dh_public_key),&rk);


        self.dh_id += 1;
        self.dhs_priv = i_dh_privkey;
        self.dhs_pub = i_dh_public_key;
        self.dhr_pub =  Some(r_dh_public_key);
        self.rk = rk;
        self.cks =  Some(cks);
        self.ckr =  Some(ckr);
        self.pn= self.ns;
        self.ns= 0;
        self.nr= 0;
        
        self.mk_skipped =  HashMap::new();
        true
    }


    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);


 
        let encrypted_data = encrypt(&mk[..16], &CONSTANT_NONCE, plaintext, &concat( self.ns, &ad)); // concat

        let header = Header::new(  self.ns,self.dh_id,encrypted_data.clone());
 
        self.ns += 1;
        let hdr = prepare_header(header); // leaving out nonce, since it is a constant, as described bysignal docs
        let mtype = if self.is_i {
            7
        } else {
            8
        };
        let mut encoded = [mtype].to_vec();
        encoded.extend(hdr);
        encoded
    }
    
    pub fn ratchet_decrypt(&mut self, header: Vec<u8>) -> Option<Vec<u8>> {
        let deserial_hdr =  unpack_header(header);
        
        let ad = if self.is_i {
            self.ad_r.clone()
        }else{
            self.ad_i.clone()
        };
        
        let plaintext = self.try_skipped_message_keys(&deserial_hdr, &deserial_hdr.ciphertext, &CONSTANT_NONCE,&ad);
        match plaintext  {
            Some(d) => Some(d),
            None => {
                
                
                self.skip_message_keys(deserial_hdr.n);
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                self.ckr = Some(ckr);
                self.nr += 1;



                let out = decrypt(&mk[..16],&CONSTANT_NONCE, &deserial_hdr.ciphertext, &concat(deserial_hdr.n, &ad));
                out
            }
        }
    }



    fn skip_message_keys(&mut self, until: u16) -> Result<(), &str> {
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
            decrypt(&mk[..16], nonce,ciphertext, &concat(header.n, &ad))
        } else {
            None
        }
    }
 
    pub fn r_receive(&mut self,input: &[u8]) -> Option<(Vec<u8>,bool)>{

        
        match input[0] {
            5 => {
                let remove_mtype = &input[1..];
                match self.ratchet_r(remove_mtype.to_vec()) {
                    Some(x) => return {
                        Some((x,true))},
                    None => return None,
                }
            },
            7 => {
                
                let remove_mtype = &input[1..];
                match self.ratchet_decrypt(remove_mtype.to_vec()){
                    Some(x) => return Some((x,false)),
                    None => return None
                }
            },
            _ => {
                return None
            }

        }
     
    }
    pub fn i_receive(&mut self,input: Vec<u8>) -> Option<(Vec<u8>,bool)>{
        match input[0] {
            6 => {
                let remove_mtype = &input[1..];
                match self.ratchet_i(remove_mtype.to_vec()) {
                    true => return None,
                    false => return None,
                }
            },
            8 => {
                let remove_mtype = &input[1..];
                match self.ratchet_decrypt(remove_mtype.to_vec()){
                    Some(x) => Some((x,false)),
                    None => None 
                }
            }
            _ => {
                return None
            }

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


fn concat_dhr(input: &[u8], dhrnonce: u8) -> Vec<u8> {

    let mut front = [dhrnonce].to_vec();
    front.extend(input);

    front
}
fn split_dhr(input: Vec<u8>) -> DhPayload {

    let payload  =DhPayload {
        pk : input[1..].to_vec(),
        nonce : input[..1][0]
    };

    payload
}

pub struct Header {
    pub n: u16, // Message Number
    pub dh_pub_id:u16,
    pub ciphertext : Vec<u8>,
}

impl Header {


    pub fn new( n: u16, dh_pub_id: u16, cipher: Vec<u8>) -> Self {
        Header {
            n : n,
            dh_pub_id: dh_pub_id,
            ciphertext: cipher,
        }
    }


}

pub struct DhPayload {
    pub pk: Vec<u8>, // public key that is sent
    pub nonce : u8, // DHRAckNonce, or DHRResNonce
}
impl DhPayload {


    pub fn new( pk : Vec<u8>, nonce : u8) -> Self {
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

    }

}*/
