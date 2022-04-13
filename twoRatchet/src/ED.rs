

use x25519_dalek_ng::{self,PublicKey, StaticSecret};

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use rand_core::{RngCore,CryptoRng};
use super::{
    encryption::{encrypt,decrypt},
    dhr::{concat,prepare_dhr,unpack_dhr},
    phypayload::{PhyPayload, deserialize},
    kdf::{kdf_ck,kdf_rk},
};
pub const CONSTANT_NONCE: [u8;13] = [42;13];


pub struct EDRatchet <Rng: CryptoRng + RngCore>
where Rng: Copy,{
    pub shared_secret : Option<[u8;32]>,
    pub rk: [u8;32],
    pub sck: [u8;32], // sending chain key
    pub rck: [u8;32], // receiving chain key
    pub fcnt_down: u16, // sending message numbering
    pub fcnt_up: u16, // receiving message numbering
    mk_skipped : BTreeMap<(u16, u16), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,
    dhr_req_nonce : u16,
    dhr_ack_nonce : u16,
    pub dh_id : u16,
    devaddr : Vec<u8>,
    rng : Rng,
}

impl<Rng: CryptoRng + RngCore> EDRatchet <Rng>
where Rng: Copy,{

    pub fn new (sk: [u8; 32],  rck: [u8; 32], sck: [u8; 32],  devaddr :Vec<u8>, rng :Rng) -> Self {

        EDRatchet {
            shared_secret: None,
            rk: sk,
            sck: sck,
            rck: rck,
            fcnt_down: 0,
            fcnt_up: 0,
            mk_skipped: BTreeMap::new(),
            tmp_pkey: None,
            tmp_skey: None,
            dhr_req_nonce: 0,
            dhr_ack_nonce: 0,
            dh_id: 0,
            devaddr,
            rng
        }

    }


    /// Function to initialize a new DHRP step
    ///

    pub fn initiate_ratch(&mut self) -> Vec<u8> {
        let i_dh_privkey : StaticSecret  = StaticSecret::new(self.rng);
        let i_dh_public_key = PublicKey::from(&i_dh_privkey);

        self.tmp_pkey = Some(i_dh_public_key);
        self.tmp_skey = Some(i_dh_privkey);

        self.dhr_req_nonce += 1;
        let concat_dhr = prepare_dhr(&i_dh_public_key.as_bytes().to_vec(), self.dhr_req_nonce);
        
        let enc = self.ratchet_encrypt(&concat_dhr, &self.devaddr.clone(),5).to_vec();
        enc
    }

    /// The actual ratcheting function, this creates the new state
    ///
    /// # Arguments
    ///
    /// * `dhr_ack_encrypted` - the encrypted dhrack message


    fn ratchet(&mut self, dhr_ack_encrypted:Vec<u8>) -> bool {

        // We first decrypt the phypayload
        let dhr_ack_serial = match self.ratchet_decrypt(dhr_ack_encrypted){    
                Some(x) => x,
                None => return false, 
        };
        // then we unpack the dhr ackknowledgement
        let dhr_ack = match unpack_dhr(dhr_ack_serial) {
            Some(dhr) => dhr,
            None => return false,
        };
        // the incoming acknowledgement should mirror the DHRP that we are at
        if self.dhr_ack_nonce >= dhr_ack.nonce{
            return false;
        }
        self.dhr_ack_nonce = dhr_ack.nonce;

        let mut buf = [0; 32];
        
        buf.copy_from_slice(&dhr_ack.pk[..32]);
        let r_dh_public_key = PublicKey::from(buf);

        let i_dh_privkey = self.tmp_skey.clone().unwrap();

        // we generate a shared secret from the incoming public key

        self.shared_secret = Some(*i_dh_privkey.diffie_hellman(&r_dh_public_key).as_bytes());

        // Then we advance the actual root chain

        let (rk, sck) = kdf_rk(self.shared_secret.unwrap(), &self.rk);
        
        let (rk, rck) = kdf_rk(self.shared_secret.unwrap(),&rk);


        // we skip a constant amount of the root chain
        if self.mk_skipped.len() > 500 {
            self.prune_mkskipped();
        }
        self.skip_message_keys(1000);

        self.dh_id += 1;

        self.rk = rk;
        self.sck =  sck;
        self.rck =  rck;
        self.fcnt_up= 0;
        self.fcnt_down= 0;
        
        true
    }
    /// Internal function for encryption, and advancing the sending chain
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr
    /// * `mtype` - the mtype, which should also be authenticated

    fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8], mtype : i8) -> Vec<u8> {
        let (cks, mk) = kdf_ck(&self.sck);
        self.sck = cks;
                
        let mut nonce = [0;13];
        self.rng.fill_bytes(&mut nonce);

        let encrypted_data = encrypt(&mk[..16], &nonce, plaintext, &concat(mtype, nonce, self.dh_id, self.fcnt_up, &ad)); // concat

        let header = PhyPayload::new(mtype, ad.try_into().unwrap(), self.fcnt_up,self.dh_id,encrypted_data.clone(),nonce);
 
        self.fcnt_up += 1;
        let hdr = header.serialize(); 
        hdr
    }

    /// Callable function for encrypting uplinks, apppends the mtype 7
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr

    pub fn ratchet_encrypt_payload(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        
        let hdr = self.ratchet_encrypt(plaintext, ad,7);
        hdr
    }


    /// Internal function for encryption, and advancing the sending chain
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr
    /// * `mtype` - the mtype, which should also be authenticated
    
    fn ratchet_decrypt(&mut self, header: Vec<u8>) -> Option<Vec<u8>> {
        let deserial_hdr =  match deserialize(&header) {
            Some(hdr) => hdr,
            None => return None
        };
        match self.try_skipped_message_keys(&deserial_hdr, &deserial_hdr.ciphertext, deserial_hdr.nonce,&self.devaddr.clone())  {
            Some(out) => Some(out),
            None => {

                self.skip_message_keys(deserial_hdr.fcnt);
                let (rck, mk) = kdf_ck(&self.rck);
                self.rck = rck;
                self.fcnt_down += 1;

                let out = decrypt(&mk[..16],&deserial_hdr.nonce, &deserial_hdr.ciphertext, &concat(deserial_hdr.mtype,deserial_hdr.nonce,deserial_hdr.dh_pub_id,deserial_hdr.fcnt, &self.devaddr));
  
                
                out
            }
        }

    

    }



    fn skip_message_keys(&mut self, until: u16)  {
           while self.fcnt_down  < until {
                let (rck, mk) = kdf_ck(&self.rck);
                self.rck = rck;
                self.mk_skipped.insert((self.dh_id, self.fcnt_down), mk);
                self.fcnt_down += 1
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
            6 => {
                match self.ratchet(input) {
                    true => return {
                        None},
                    false => return {
                        None
                    },
                }
            },
            8 => {
                match self.ratchet_decrypt(input){
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





