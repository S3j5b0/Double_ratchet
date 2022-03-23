extern crate alloc;

use alloc::vec::Vec;


use super::{
    ratchfuncs::{Header }
};
/// Concat header with associated data
pub fn concat(n: u16, ad:&[u8]) ->Vec<u8> {
    let mut n = n.to_be_bytes().to_vec();
    n.extend(ad);
    n
}


pub fn prepare_header(msg: Header) ->Vec<u8> {
    let nbytes = msg.n.to_be_bytes();
    let dh_id_bytes = msg.dh_pub_id.to_be_bytes();
    let mut front = [nbytes, dh_id_bytes].concat().to_vec();
    front.extend(msg.ciphertext);

    front
}
pub fn unpack_header(encoded: Vec<u8>) ->Header {
    let n = ((encoded[0] as u16) << 8) | encoded[1] as u16;
    let dh_id = ((encoded[2] as u16) << 8) | encoded[3] as u16;
    let cipher = &encoded[4..];
    Header::new(  n,dh_id,cipher.to_vec())
}


