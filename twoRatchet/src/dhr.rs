extern crate alloc;

use alloc::vec::Vec;



/// Concat header with associated data
pub fn concat(mtype: i8,nonce : [u8;13],dh_id : u16,n: u16, devaddr:&[u8]) ->Vec<u8> {
    let mut buffer : Vec<u8> = Vec::with_capacity(17+devaddr.len());
    buffer.extend_from_slice(devaddr);
    buffer.extend_from_slice(&[mtype as u8]);
    buffer.extend_from_slice(&nonce);
    buffer.extend([n.to_be_bytes(), dh_id.to_be_bytes()].concat().to_vec());
    buffer
}


pub fn prepare_dhr(pk: &[u8], dhrnonce: u16) -> Vec<u8> {

    let mut buffer : Vec<u8> = Vec::with_capacity(34);
    buffer.extend_from_slice(&dhrnonce.to_be_bytes());
    buffer.extend_from_slice(pk);
    
    buffer
}
pub fn unpack_dhr(input: Vec<u8>) -> Result<DhPayload, &'static str>{
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
    .map(|(_, dhr)| dhr) {
        Ok(x) => return Ok(x),
        _=> return Err("Could not parse dhr"),
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
