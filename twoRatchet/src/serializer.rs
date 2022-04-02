extern crate alloc;

use alloc::vec::Vec;
use bytes::{BytesMut, BufMut};


use super::{
    ratchfuncs::{DhPayload }
};
/// Concat header with associated data
pub fn concat(mtype: u8,nonce : [u8;13],dh_id : u16,n: u16, ad:&[u8]) ->Vec<u8> {
    let dh_id_byt = dh_id.to_be_bytes();
    let n = n.to_be_bytes();
    let mut out = [mtype].to_vec();
    out.extend(nonce);
    out.extend(n);
    out.extend(ad);
    out.extend(dh_id_byt);
    out

}

/*
pub fn prepare_payload(msg: PhyPayload) ->Vec<u8> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(msg.mtype);
    buf.put_slice(&msg.nonce);
    buf.put_slice(&msg.devaddr);
    buf.put_u16(msg.fcnt);
    buf.put_u16(msg.dh_pub_id);
    buf.put_slice(&msg.ciphertext);

    buf.to_vec()
}
pub fn unpack_payload(encoded: Vec<u8>) ->Option<PhyPayload> {

    if encoded.len() < 22{
        return None
    }
    let mtype = encoded[0];
    let nonce :[u8;13]= encoded[1..14].try_into().unwrap();
    

    let devaddr = &encoded[14..18];
    
    let fcnt = ((encoded[18] as u16) << 8) | encoded[19] as u16;

    let dh_id = ((encoded[20] as u16) << 8) | encoded[21] as u16;
    let cipher = &encoded[22..];

    Some(PhyPayload::new(mtype,devaddr.to_vec(),fcnt,dh_id,cipher.to_vec(),nonce))
}*/
pub fn prepare_dhr(input: &[u8], dhrnonce: u16) -> Vec<u8> {

    let nonce_bytes = dhrnonce.to_be_bytes();
    let mut front = nonce_bytes.to_vec();
    front.extend(input);

    front
}
pub fn unpack_dhr(input: Vec<u8>) -> Option<DhPayload> {
    if input.len() != 34{
        return None
    }

    let nonce_val = ((input[0] as u16) << 8) | input[1] as u16;
    let payload  =DhPayload {
        pk : input[2..].to_vec(),
        nonce : nonce_val
    };

    Some(payload)
}

