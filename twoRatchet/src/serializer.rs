extern crate alloc;
use rand_core::{OsRng,};
use core::result::Result;
use alloc::vec::Vec;
use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek_ng::{self, PublicKey};

use super::{
    ratchfuncs::{Header,DhPayload }
};
use serde::Serialize; 
/// Concat header with associated data
pub fn concat(dh_id: usize, pn : usize, n: usize, ad:&[u8]) ->Vec<u8> {

    let raw_msg = (
        Bytes::new(&ad),
        dh_id,
        pn,
        n,
    );

    encode_sequence(raw_msg)
}
pub fn serialize_dhr(dh: DhPayload) ->Vec<u8> {
    let tmp : usize = 1;
    let raw_msg = (
        Bytes::new(&dh.pk),
        dh.nonce,
    );
    encode_sequence(raw_msg)
}
pub fn deserialize_dhr(serial_pk: &[u8]) ->DhPayload{


    let mut temp = Vec::with_capacity(serial_pk.len() );

    let raw_pk :  (ByteBuf,u16)=  decode_sequence(serial_pk, 2, &mut temp).unwrap();


    

    DhPayload {
        pk:raw_pk.0.to_vec(),
        nonce:raw_pk.1,
    }
    
}
pub fn serialize_pk(pk: &Vec<u8>) ->Vec<u8> {
    let tmp : usize = 1;
    let raw_msg = (
        Bytes::new(&pk),
        tmp,
    );
    encode_sequence(raw_msg)
}
pub fn deserialize_pk(serial_pk: &[u8]) ->Vec<u8> {


    let mut temp = Vec::with_capacity(serial_pk.len() + 1);

    let raw_pk :  (ByteBuf,usize)=  decode_sequence(serial_pk, 2, &mut temp).unwrap();


    raw_pk.0.to_vec()
    
}
pub fn serialize_header(msg: &Header) ->Vec<u8> {

    let raw_msg = (
        msg.dh_pub_id,
        &msg.pn,
        msg.n,
        Bytes::new(&msg.ciphertext)
    );

    encode_sequence(raw_msg)
}
pub fn deserialize_header(serial_header: &[u8]) -> Option<Header> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(serial_header.len() + 1);

    let raw_msg :Option<( usize,usize ,usize, ByteBuf)>=  decode_sequence(serial_header, 4, &mut temp);


    // On success, just move the items into the "nice" message structure
    if raw_msg == None{
        return None
    } else {
        let raw = raw_msg.clone().unwrap();
       return  Some(Header {
            dh_pub_id: raw.0,
            pn : raw.1,
            n : raw.2,
            ciphertext: raw.3.to_vec()
        })
    }


}
 fn decode_sequence<'a, T>(
    bytes: &[u8],
    n_items: usize,
    tmp_vec: &'a mut Vec<u8>,
) -> Option<T>
where
    T: serde::Deserialize<'a>,
{
    // We receive a sequence of CBOR items. For parsing we need an array, so
    // start a CBOR array of the given length.
    tmp_vec.push(array_byte(n_items));
    // After the start byte, insert the message (sequence of CBOR items)
    tmp_vec.extend(bytes);

    // Now we can try to deserialize that
    let res = serde_cbor::from_slice(tmp_vec).unwrap_or(None);
    res
}

fn array_byte(n: usize) -> u8 {
    match n {
        _ if n > 23 => 0,
        // The major type for arrays is indicated by the three leftmost bits.
        // By doing bitwise OR with the number of items, we assign the
        // remaining bits for the number of elements.
        n => 0b100_00000 | n as u8,
    }
}
//[131, 1, 67, 100, 100, 0, 3]
 fn encode_sequence(object: impl Serialize) -> Vec<u8>{
    // We serialize something that encodes as a CBOR array.
    // What we want is just the sequence of items, so we can omit the
    // first byte (indicating array type and length), and get the items.
    // That only works as long as we have at most 23 items, after that it
    // takes an additional byte to indicate the length.
    serialize(object, 1)
}

fn serialize(object: impl Serialize, offset: usize) -> Vec<u8> {
    // Serialize to byte vector
    let mut v = serde_cbor::to_vec(&object).expect("error during serialization");
    // Return everything starting from the offset
    v.drain(offset..).collect()
}
 fn decode<'a, T>(bytes: &'a [u8]) -> T
where
    T: serde::Deserialize<'a>,
{
    serde_cbor::from_slice(bytes).expect("eror during deserialization")
}


