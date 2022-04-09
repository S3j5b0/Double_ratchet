



use x25519_dalek_ng::{self,PublicKey, StaticSecret};

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use rand_core::{OsRng,RngCore};
use super::{
    encryption::{encrypt,decrypt},
    dhr::{concat,prepare_dhr,unpack_dhr},
    phypayload::{PhyPayload, deserialize},
    kdf::{kdf_ck,kdf_rk},
};



pub struct ASRatchet {
    pub shared_secret : Option<[u8;32]>,
    pub rk: [u8;32],
    pub sck: Option<[u8;32]>, // sending chain key
    pub rck: Option<[u8;32]>, // receiving chain key
    pub fcnt_rcv: u16, // sending message numbering
    pub fcnt_send: u16, // receiving message numbering
    mk_skipped : BTreeMap<(u16, u16), [u8; 32]>,
    tmp_shared_secret : Option<[u8;32]>,
    dhr_ack_nonce : u16,
    dhr_res_nonce : u16,
    pub dh_id : u16,
    devaddr : Vec<u8>,
}

impl ASRatchet {



    pub fn new(sk: [u8; 32], rck: [u8; 32], sck: [u8; 32],  devaddr :Vec<u8>) -> Self {

        ASRatchet {
            shared_secret : None,
            rk: sk,
            sck: Some(sck),
            rck: Some(rck),
            fcnt_send: 0,
            fcnt_rcv: 0,
            mk_skipped: BTreeMap::new(),
            tmp_shared_secret:None,
            dhr_ack_nonce: 0,
            dhr_res_nonce: 0,
            dh_id: 0,
            devaddr,
        }
    }

    fn ratchet(&mut self, dhr_encrypted:Vec<u8>) -> Option<Vec<u8>> {

        // first, attempt to decrypt incoming key
        let dhr_serial = match self.ratchet_decrypt(dhr_encrypted) {
                Some(x) => x,
                None => return None,
        };
        
        // then we deserialize dhr and create our own dhrackknowledgement message
        let dhr_req = match unpack_dhr(dhr_serial){
            Some(dhr) => dhr,
            None => return None,
        };

        self.dhr_res_nonce = dhr_req.nonce;

        let mut buf = [0; 32];
        buf.copy_from_slice(&dhr_req.pk[..32]);
        let i_dh_public_key = PublicKey::from(buf);

        let r_dh_privkey : StaticSecret  = StaticSecret::new(OsRng);
        let r_dh_public_key = PublicKey::from(&r_dh_privkey);

        // create own drh ack nonce message
        
        self.dhr_ack_nonce += 1;

        
        let concat_dhr = prepare_dhr(&r_dh_public_key.as_bytes().to_vec(), self.dhr_ack_nonce);
        let dhr_ack = self.ratchet_encrypt(&concat_dhr, &self.devaddr.clone(),6).to_vec();
            
        self.tmp_shared_secret = Some(*r_dh_privkey.diffie_hellman(&i_dh_public_key).as_bytes());

        // return the key
        Some(dhr_ack) 
        
    }
    fn finalize_ratchet(&mut self)   {
        self.shared_secret = self.tmp_shared_secret;
        
        let (rk, rck) = kdf_rk(self.shared_secret.unwrap(), &self.rk);
        
        let (rk, sck) = kdf_rk(self.shared_secret.unwrap(),&rk);
        if self.mk_skipped.len() > 500 {
            self.prune_mkskipped();
        }
        self.skip_message_keys(20);
        self.dh_id += 1;


        self.rk = rk;
        self.sck =  Some(sck);
        self.rck =  Some(rck);
        self.fcnt_send= 0;
        self.fcnt_rcv= 0;


    }



    fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8], mtype : u8) -> Vec<u8> {
        let (cks, mk) = kdf_ck(&self.sck.unwrap());
        self.sck = Some(cks);
                
        let mut nonce = [0;13];
        OsRng.fill_bytes(&mut nonce);


        let encrypted_data = encrypt(&mk[..16], &nonce, plaintext, &concat(mtype, nonce, self.dh_id, self.fcnt_send, &ad)); // concat





        let header = PhyPayload::new(mtype, ad.try_into().unwrap(), self.fcnt_send,self.dh_id,encrypted_data.clone(),nonce);
 
        self.fcnt_send += 1;
        let hdr = header.serialize(); 
        hdr
    }

    pub fn ratchet_encrypt_payload(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        
        let hdr = self.ratchet_encrypt(plaintext, ad,8);
        hdr
    }
    
    fn ratchet_decrypt(&mut self, header: Vec<u8>) -> Option<Vec<u8>> {


        let deserial_hdr =  match deserialize(&header) {
            Some(hdr) => hdr,
            None => return None
        };

        if self.dh_id < deserial_hdr.dh_pub_id {

            self.finalize_ratchet();
        }        

        match self.try_skipped_message_keys(&deserial_hdr, &deserial_hdr.ciphertext, deserial_hdr.nonce,&self.devaddr.clone())  {
            Some(out) => Some(out),
            None => {

                self.skip_message_keys(deserial_hdr.fcnt);
                let (rck, mk) = kdf_ck(&self.rck.unwrap());
                self.rck = Some(rck);
                self.fcnt_rcv += 1;

                
                let out = decrypt(&mk[..16],&deserial_hdr.nonce, &deserial_hdr.ciphertext, &concat(deserial_hdr.mtype,deserial_hdr.nonce,deserial_hdr.dh_pub_id,deserial_hdr.fcnt, &self.devaddr));
  
                
                out
            }
        }

    

    }



    fn skip_message_keys(&mut self, until: u16)  {

        if self.rck == None {
            return 
        }
           while self.fcnt_rcv  < until {
                let (ckr, mk) = kdf_ck(&self.rck.unwrap());
                self.rck = Some(ckr);
                self.mk_skipped.insert((self.dh_id, self.fcnt_rcv), mk);
                self.fcnt_rcv += 1
                }
                return
    }
    

    fn try_skipped_message_keys(&mut self, header: &PhyPayload, ciphertext: &[u8], nonce:[u8;13], ad: &[u8]) -> Option<Vec<u8>> {
        match self.mk_skipped.contains_key(&(header.dh_pub_id, header.fcnt)) {
            true => {
                
            let mk = *self.mk_skipped.get(&(header.dh_pub_id, header.fcnt))
                .unwrap();
            self.mk_skipped.remove(&(header.dh_pub_id, header.fcnt)).unwrap();

            decrypt(&mk[..16], &nonce,ciphertext, &concat(header.mtype,nonce,header.dh_pub_id,header.fcnt, &ad))
            },
            false => return None
        } 
    }

    fn prune_mkskipped(&mut self) {
        let n = self.mk_skipped.keys().next().map(|v| v.0).unwrap();
        self.mk_skipped.retain(|key, _| {
            key.0 != n
        });
        
    }
    pub fn receive(&mut self,input: Vec<u8>) -> Option<(Vec<u8>,bool)>{

        
        match input[0] {
            5 => {
                match self.ratchet(input) {
                    Some(x) => return {
                        Some((x,true))},
                    None => {
                        return None},
                }
            },
            7 => {
                
                match self.ratchet_decrypt(input){
                    Some(x) => return Some((x,false)),
                    None => return None
                }
            },
            _ => {
                return None
            }

        }
     
    }


}
