extern crate alloc;

use alloc::vec::Vec;


use super::{
    ratchfuncs::{PhyPayload,DhPayload }
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


pub fn prepare_header(msg: Header) ->Vec<u8> {
    let mut out = [msg.mtype].to_vec();
    out.extend(msg.nonce);
    let fcnt_bytes = msg.fcnt.to_be_bytes();
    out.extend(fcnt_bytes);
    let dh_id_bytes = msg.dh_pub_id.to_be_bytes();
    out.extend(dh_id_bytes);
    out.extend(msg.ciphertext);
    out
}
pub fn unpack_header(encoded: Vec<u8>) ->Header {
    let mtype = encoded[0];
    let nonce :[u8;13]= encoded[1..14].try_into().unwrap();
    
    let fcnt = ((encoded[14] as u16) << 8) | encoded[15] as u16;
    let dh_id = ((encoded[16] as u16) << 8) | encoded[17] as u16;
    
    let cipher = &encoded[18..];
    Header::new(mtype,fcnt,dh_id,cipher.to_vec(),nonce)
}
pub fn concat_dhr(input: &[u8], dhrnonce: u16) -> Vec<u8> {

    let nonce_bytes = dhrnonce.to_be_bytes();
    let mut front = nonce_bytes.to_vec();
    front.extend(input);

    front
}
pub fn split_dhr(input: Vec<u8>) -> DhPayload {

    let nonce_val = ((input[0] as u16) << 8) | input[1] as u16;
    let payload  =DhPayload {
        pk : input[2..].to_vec(),
        nonce : nonce_val
    };

    payload
}

