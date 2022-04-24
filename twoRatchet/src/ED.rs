

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


pub struct EDRatchet <Rng: CryptoRng + RngCore>
{
    rk: [u8;32],
    sck: [u8;32], // sending chain key
    rck: [u8;32], // receiving chain key
    pub fcnt_down: u16, // sending message numbering
    pub fcnt_up: u16, // receiving message numbering
    mk_skipped : BTreeMap<(u16, u16), [u8; 32]>,
    tmp_pkey : Option<PublicKey>,
    tmp_skey : Option<StaticSecret>,
    shared_secret : [u8;32],
    dhr_req_nonce : u16,
    dhr_ack_nonce : u16,
    dh_id : u16,
    devaddr : [u8;4],
    rng : Rng,
}

impl<Rng: CryptoRng + RngCore> EDRatchet <Rng>
{
    pub fn new (rk: [u8; 32],  rck: [u8; 32], sck: [u8; 32],  devaddr :[u8;4], rng :Rng) -> Self {
        EDRatchet {
            rk,
            sck,
            rck,
            fcnt_down: 0,
            fcnt_up: 0,
            mk_skipped: BTreeMap::new(),
            tmp_pkey: None,
            tmp_skey: None,
            shared_secret: [0;32],
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
        let ed_dh_privkey : StaticSecret  = StaticSecret::new(&mut self.rng);
        let ed_dh_public_key = PublicKey::from(&ed_dh_privkey);
        self.tmp_pkey = Some(ed_dh_public_key);
        self.tmp_skey = Some(ed_dh_privkey);
        self.dhr_req_nonce += 1;
        let dhr_ack = prepare_dhr(ed_dh_public_key.as_bytes(), self.dhr_req_nonce);
        
        self.ratchet_encrypt(&dhr_ack,5)
    }

    /// The actual ratcheting function, this creates the new state
    ///
    /// # Arguments
    ///
    /// * `dhr_ack_encrypted` - the encrypted dhrack message
    /// Returns an empty Ok, in the case that the ratchet completed successfully


    fn ratchet(&mut self, dhr_ack_encrypted:Vec<u8>) -> Result<(),&str> {

        // We first decrypt the phypayload
        let dhr_ack_serial = self.ratchet_decrypt(dhr_ack_encrypted)?;
        // then we unpack the dhr ackknowledgement
        let dhr_ack =  unpack_dhr(dhr_ack_serial)?;
        // the incoming acknowledgement should mirror the DHRP that we are at
        if self.dhr_ack_nonce >= dhr_ack.nonce{
            return Err("Received old DHRack");
        }
        self.dhr_ack_nonce = dhr_ack.nonce;

        let mut buf = [0; 32];
        
        buf.copy_from_slice(&dhr_ack.pk[..32]);
        let as_dh_public_key = PublicKey::from(buf);

        let ed_dh_privkey = self.tmp_skey.as_ref().unwrap();

        // we generate a shared secret from the incoming public key

        self.shared_secret = *ed_dh_privkey.diffie_hellman(&as_dh_public_key).as_bytes();

        // Then we advance the actual root chain

        let (rk, sck) = kdf_rk(self.shared_secret, &self.rk);
        
        let (rk, rck) = kdf_rk(self.shared_secret,&rk);


        // we skip a constant amount of the root chain
        if self.mk_skipped.len() > 500 {
            self.prune_mkskipped();
        }
        self.skip_message_keys(500);

        self.dh_id += 1;

        self.rk = rk;
        self.sck =  sck;
        self.rck =  rck;
        self.fcnt_up= 0;
        self.fcnt_down= 0;
        
        Ok(())
    }
    /// Internal function for encryption, and advancing the sending chain
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr
    /// * `mtype` - the mtype, which should also be authenticated

    fn ratchet_encrypt(&mut self, plaintext: &[u8], mtype : i8) -> Vec<u8> {
        let (sck, mk) = kdf_ck(&self.sck);
        self.sck = sck;
                
        let mut nonce = [0;13];
        self.rng.fill_bytes(&mut nonce);

        let encrypted_data = encrypt(&mk[..16], 
                                    &nonce, plaintext, 
                                    &concat(
                                        mtype, 
                                        nonce, 
                                        self.dh_id, 
                                        self.fcnt_up, 
                                        self.devaddr)); 

        let phypayload = PhyPayload::new(mtype, self.devaddr, self.fcnt_up,self.dh_id,encrypted_data,nonce);
 
        self.fcnt_up += 1;
        phypayload.serialize()  
    }

    /// Callable function for encrypting uplinks, apppends the mtype 7
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr

    pub fn ratchet_encrypt_payload(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.ratchet_encrypt(plaintext,7)
    }


    /// Internal function for encryption, and advancing the sending chain
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The stuff to be encrypted
    /// * `ad` - associated data, most likely the devaddr
    /// * `mtype` - the mtype, which should also be authenticated
    
    fn ratchet_decrypt(&mut self, phypayload: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        let deserial_phy = deserialize(&phypayload)?;

        match self.try_skipped_message_keys(&deserial_phy)  {
            Some(out) => Ok(out),
            None => {

                self.skip_message_keys(deserial_phy.fcnt);
                let (rck, mk) = kdf_ck(&self.rck);
                self.rck = rck;
                self.fcnt_down += 1;

                decrypt(&mk[..16],
                    &deserial_phy.nonce, 
                    &deserial_phy.ciphertext, 
                    &concat(deserial_phy.mtype,
                            deserial_phy.nonce,
                            deserial_phy.dh_pub_id,
                            deserial_phy.fcnt, 
                            deserial_phy.devaddr))
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
    }
    

    fn try_skipped_message_keys(&mut self, phypayload: &PhyPayload) -> Option<Vec<u8>> {
        match self.mk_skipped.contains_key(&(phypayload.dh_pub_id, phypayload.fcnt)) {
            true => {
                
            let mk = *self.mk_skipped.get(&(phypayload.dh_pub_id, phypayload.fcnt))
                .unwrap();
            self.mk_skipped.remove(&(phypayload.dh_pub_id, phypayload.fcnt)).unwrap();

            match decrypt(&mk[..16], 
                &phypayload.nonce,
                &phypayload.ciphertext, 
                &concat(phypayload.mtype,
                        phypayload.nonce,
                        phypayload.dh_pub_id,
                        phypayload.fcnt, 
                        self.devaddr)) 
                    {
                    Ok(x) => Some(x),
                    Err(_) => None,
                }            },
            false => None
        } 
    }

    fn prune_mkskipped(&mut self) {
        let n = self.mk_skipped.keys().next().map(|v| v.0).unwrap();
        self.mk_skipped.retain(|key, _| {
            key.0 != n
        });
        
    }
 
    pub fn receive(&mut self,input: Vec<u8>) -> Result<Option<Vec<u8>>,&str>{
        match input[0] {
            6 => {
                match self.ratchet(input) {
                    Ok(()) => Ok(None),
                    Err(s) => Err(s),
                }
            },
            8 => {
                match self.ratchet_decrypt(input){
                    Ok(x) => Ok(Some(x)),
                    Err(s) => Err(s), 
                }
            }
            _ => {
                Err("unkown mtype")
            }

        }
    }

}
