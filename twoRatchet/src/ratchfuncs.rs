
use x25519_dalek_ng::{self, SharedSecret,PublicKey, StaticSecret};
use hkdf::Hkdf;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use sha2::Sha256;
use rand_core::{OsRng,RngCore};
use super::{
    encryption::{encrypt,decrypt},
    serializer::{concat,prepare_header,unpack_header,concat_dhr,split_dhr}
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];


pub struct state {
    pub is_i : bool,
    shared_secret : Option<[u8;32]>,
    pub rk: [u8;32],
    pub sck: Option<[u8;32]>, // sending chain key
    pub rck: Option<[u8;32]>, // receiving chain key
    pub ns: u16, // sending message numbering
    nr: u16, // receiving message numbering
    mk_skipped : BTreeMap<(u16, u16), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,
    dhr_ack_nonce : u16,
    dhr_res_nonce : u16,
    dh_id : u16,
    ad_i : Vec<u8>,
    ad_r : Vec<u8>
}

impl state {



    pub fn init_r(sk: [u8; 32], ckr: [u8; 32], sck: [u8; 32],  ad_i :Vec<u8>, ad_r:Vec<u8>) -> Self {

        state {
            is_i : false,

            shared_secret : None,
            rk: sk,
            sck: Some(sck),
            rck: Some(ckr),
            ns: 0,
            nr: 0,
            mk_skipped: BTreeMap::new(),
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
    pub fn init_i(sk: [u8; 32],  rck: [u8; 32], sck: [u8; 32],ad_i :Vec<u8>,ad_r: Vec<u8>) -> Self {

        let i_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let i_dh_public_key = PublicKey::from(&i_dh_privkey);


    

        let  state  = state {
            is_i: true,
            shared_secret: None,
            rk: sk,
            sck: Some(sck),
            rck: Some(rck),
            ns: 0,
            nr: 0,
            mk_skipped: BTreeMap::new(),
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


        let concat_dhr = concat_dhr(&i_dh_public_key.as_bytes().to_vec(), self.dhr_res_nonce+1);


        
        let enc = self.ratchet_encrypt(&concat_dhr, &self.ad_i.clone()).to_vec();
        let mut encoded = [5].to_vec();
        encoded.extend(enc);
        encoded
    }
    pub fn ratchet_r(&mut self, dhr_encrypted:Vec<u8>) -> Option<Vec<u8>> {

        // first, attempt to decrypt incoming key
        let dhr_serial = match self.ratchet_decrypt(dhr_encrypted) {
                Some(x) => x,
                None => return None,
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

        
        let concat_dhr = concat_dhr(&r_dh_public_key.as_bytes().to_vec(), self.dhr_ack_nonce);
        let dhr_ack = self.ratchet_encrypt(&concat_dhr, &self.ad_r.clone()).to_vec();
            
        
        let mut encoded = [6].to_vec();
        encoded.extend(dhr_ack);

        self.shared_secret = Some(*r_dh_privkey.diffie_hellman(&i_dh_public_key).as_bytes());

        // We then do the ratchet
        let (rk, ckr) = kdf_rk(self.shared_secret.unwrap(), &self.rk);
        
        let (rk, cks) = kdf_rk(self.shared_secret.unwrap(),&rk);

        self.dh_id += 1;

        self.rk = rk;
        self.sck =  Some(cks);
        self.rck =  Some(ckr);
        self.ns= 0;
        self.nr= 0;
        self.mk_skipped =  BTreeMap::new();

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

        // We then do the ratchet

        self.shared_secret = Some(*i_dh_privkey.diffie_hellman(&r_dh_public_key).as_bytes());

        let (rk, cks) = kdf_rk(self.shared_secret.unwrap(), &self.rk);
        
        let (rk, ckr) = kdf_rk(self.shared_secret.unwrap(),&rk);


        self.dh_id += 1;

        self.rk = rk;
        self.sck =  Some(cks);
        self.rck =  Some(ckr);
        self.ns= 0;
        self.nr= 0;
        
        self.mk_skipped =  BTreeMap::new();
        true
    }


    fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let (cks, mk) = kdf_ck(&self.sck.unwrap());
        self.sck = Some(cks);
                
        let mut nonce = [0;13];
        OsRng.fill_bytes(&mut nonce);

        let encrypted_data = encrypt(&mk[..16], &nonce, plaintext, &concat(&nonce, self.dh_id, self.ns, &ad)); // concat
        let header = Header::new(  self.ns,self.dh_id,encrypted_data.clone(),nonce.to_vec());
 
        self.ns += 1;
        let hdr = prepare_header(header); // leaving out nonce, since it is a constant, as described bysignal docs
        hdr
    }

    pub fn ratchet_encrypt_payload(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let hdr = self.ratchet_encrypt(plaintext, ad);
        let mtype = if self.is_i {
            7
        } else {
            8
        };
        let mut encoded = [mtype].to_vec();
        encoded.extend(hdr);
        encoded
    }
    
    fn ratchet_decrypt(&mut self, header: Vec<u8>) -> Option<Vec<u8>> {
        let deserial_hdr =  unpack_header(header);
        
        
        let ad = if self.is_i {
            self.ad_r.clone()
        }else{
            self.ad_i.clone()
        };
        
        
        
        match self.try_skipped_message_keys(&deserial_hdr, &deserial_hdr.ciphertext, &deserial_hdr.nonce,&ad)  {
            Some(out) => Some(out),
            None => {
                
                self.skip_message_keys(deserial_hdr.fcnt);
                let (ckr, mk) = kdf_ck(&self.rck.unwrap());
                self.rck = Some(ckr);
                self.nr += 1;

                let out = decrypt(&mk[..16],&deserial_hdr.nonce, &deserial_hdr.ciphertext, &concat(&deserial_hdr.nonce,self.dh_id,deserial_hdr.fcnt, &ad));
                out
            }
        }
    }



    fn skip_message_keys(&mut self, until: u16)  {
        // we will not accept more skips than 200;
        if self.nr + 200 < until {
            return 
        }
        if self.rck == None {
            return 
        }
            while self.nr  < until {
                let (ckr, mk) = kdf_ck(&self.rck.unwrap());
                self.rck = Some(ckr);
                self.mk_skipped.insert((self.dh_id, self.nr), mk);
                self.nr += 1
                }
                return
        }
    

    fn try_skipped_message_keys(&mut self, header: &Header, ciphertext: &[u8], nonce: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
        match self.mk_skipped.contains_key(&(header.dh_pub_id, header.fcnt)) {
            true => {
            let mk = *self.mk_skipped.get(&(header.dh_pub_id, header.fcnt))
                .unwrap();
            self.mk_skipped.remove(&(header.dh_pub_id, header.fcnt)).unwrap();
            decrypt(&mk[..16], nonce,ciphertext, &concat(nonce,self.dh_id,header.fcnt, &ad))
            },
            false => return None
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


fn kdf_rk(salt: [u8;32],  input: &[u8]) -> ([u8;32],[u8;32]) {
    
    let mut output = [0u8; 64];

    let h = Hkdf::<Sha256>::new(Some(&salt),input);

    h.expand(b"ConstantIn", &mut output).unwrap();

    let (rk,ck) = output.split_at(32);
    
    (rk.try_into().unwrap(),ck.try_into().unwrap())
}

 fn kdf_ck(input: &[u8]) -> ([u8;32],[u8;32]) {
    let mut output = [0u8; 64];
    // kdf_ck should have a constant 
    let salt = &[1;32];
    let h = Hkdf::<Sha256>::new(Some(salt),input);

    h.expand(b"ConstantIn", &mut output).unwrap();

    let (rk,ck) = output.split_at(32);

    (rk.try_into().unwrap(),ck.try_into().unwrap())
}




pub struct Header {
    pub fcnt: u16, // Message Number
    pub dh_pub_id:u16,
    pub ciphertext : Vec<u8>,
    pub nonce : Vec<u8>
}

impl Header {


    pub fn new( n: u16, dh_pub_id: u16, cipher: Vec<u8>,nonce :Vec<u8>) -> Self {
        Header {
            fcnt : n,
            dh_pub_id: dh_pub_id,
            ciphertext: cipher,
            nonce: nonce
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
