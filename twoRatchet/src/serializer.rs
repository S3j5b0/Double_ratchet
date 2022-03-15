extern crate alloc;
use rand_core::{OsRng,};

use alloc::vec::Vec;
use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek_ng::{self, PublicKey};

use super::{
    ratchfuncs::{Header}
};
use serde::Serialize; 
/// Concat header with associated data
pub fn serialize_header(msg: &Header) ->Vec<u8> {

    let raw_msg = (
        msg.public_key.as_bytes().to_vec(),
        &msg.pn,
        msg.n,
    );

    encode_sequence(raw_msg)
}

pub fn deserialize_header(msg: &[u8]) -> (Vec<u8>,Header) {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let raw_msg: (ByteBuf,ByteBuf, usize ,usize) =
        decode_sequence(msg, 4, &mut temp);


    // On success, just move the items into the "nice" message structure
    let mut pk_bytes = [0; 32];
    let ad = raw_msg.0.to_vec();
    pk_bytes.copy_from_slice(&raw_msg.1.to_vec());

    let pk = PublicKey::from(pk_bytes);
    (ad, Header {
        public_key : pk,
        pn : raw_msg.2,
        n : raw_msg.3,
    })
}
 fn decode_sequence<'a, T>(
    bytes: &[u8],
    n_items: usize,
    tmp_vec: &'a mut Vec<u8>,
) -> T
where
    T: serde::Deserialize<'a>,
{
    // We receive a sequence of CBOR items. For parsing we need an array, so
    // start a CBOR array of the given length.
    tmp_vec.push(array_byte(n_items));
    // After the start byte, insert the message (sequence of CBOR items)
    tmp_vec.extend(bytes);

    // Now we can try to deserialize that
    serde_cbor::from_slice(tmp_vec).expect("bad slice")
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


