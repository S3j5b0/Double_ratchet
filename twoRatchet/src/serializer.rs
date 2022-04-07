extern crate alloc;

use alloc::vec::Vec;



/// Concat header with associated data
pub fn concat(mtype: u8,nonce : [u8;13],dh_id : u16,n: u16, devaddr:&[u8]) ->Vec<u8> {
    let dh_id_byt = dh_id.to_be_bytes();
    let n = n.to_be_bytes();
    let mut out = [mtype].to_vec();
    out.extend(nonce);
    out.extend(n);
    out.extend(devaddr);
    out.extend(dh_id_byt);
    out

}


pub fn prepare_dhr(pk: &[u8], dhrnonce: u16) -> Vec<u8> {

    let mut buffer : Vec<u8> = Vec::with_capacity(34);
    buffer.extend_from_slice(&dhrnonce.to_be_bytes());
    buffer.extend_from_slice(pk);
    
    buffer
}
pub fn unpack_dhr(input: Vec<u8>) -> Option<DhPayload> {
    use nom::{Finish, Parser};

    fn parse_array<const N: usize>(input: &[u8]) -> nom::IResult<&[u8], [u8; N]> {
        nom::bytes::complete::take(N)
            .map(|data: &[u8]| data.try_into().unwrap())
            .parse(input)
    }

    match nom::combinator::complete(
        nom::sequence::tuple((
            nom::number::complete::be_u16,
            parse_array,
        ))
        .map(|(nonce, pk) :(_, [_; 32])| DhPayload {
            pk : pk.to_vec(),
            nonce,
        }),
    )
    .parse(&input)
    .finish()
    .map(|(_, header)| header) {
        Ok(x) => return Some(x),
        _=> return None,
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
