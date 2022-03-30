extern crate alloc;

use alloc::vec::Vec;


use super::{
    ratchfuncs::{Header,DhPayload }
};
/// Concat header with associated data
pub fn concat(nonce : &[u8],dh_id : u16,n: u16, ad:&[u8]) ->Vec<u8> {
    let dh_id_byt = dh_id.to_be_bytes();
    let  n = n.to_be_bytes();
    let mut out = [dh_id_byt,n].concat().to_vec();
    out.extend(ad);
    out.extend(nonce);
    out
}


pub fn prepare_header(msg: Header) ->Vec<u8> {
    let fcnt_bytes = msg.fcnt.to_be_bytes();
    let mut out = msg.nonce;
    out.extend(fcnt_bytes);
    let dh_id_bytes = msg.dh_pub_id.to_be_bytes();
    out.extend(dh_id_bytes);
    out.extend(msg.ciphertext);
    println!("headerin {:?}", out);
    out
}
pub fn unpack_header(encoded: Vec<u8>) ->Header {
    println!("header out {:?}", encoded);
    let nonce = &encoded[..13];
    let fcnt = ((encoded[13] as u16) << 8) | encoded[14] as u16;
    let dh_id = ((encoded[15] as u16) << 8) | encoded[16] as u16;
    
    let cipher = &encoded[17..];
    Header::new(  fcnt,dh_id,cipher.to_vec(),nonce.to_vec())
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

