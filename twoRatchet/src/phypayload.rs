extern crate alloc;

use alloc::vec::Vec;

pub struct PhyPayload {
    pub mtype: u8,
    pub nonce: [u8; 13],
    pub fcnt: u16, // Message Number
    pub devaddr : [u8;4],
    pub dh_pub_id: u16,
    pub ciphertext: Vec<u8>,
    
}

impl PhyPayload {
    pub fn new( mtype : u8,devaddr:[u8;4],n: u16, dh_pub_id: u16, cipher: Vec<u8>,nonce :[u8;13]) -> Self {
        PhyPayload {
            mtype: mtype,
            nonce: nonce,
            devaddr:devaddr,
            fcnt : n,
            dh_pub_id: dh_pub_id,
            ciphertext: cipher,
            
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        // Unpack to ensure that you don't forget a field
        let PhyPayload {
            mtype,
            nonce,
            fcnt,
            devaddr,
            dh_pub_id,
            ciphertext,
            
        } = self;

        let mut buffer = Vec::new();

        buffer.extend_from_slice(&mtype.to_be_bytes());
        buffer.extend_from_slice(nonce);
        buffer.extend_from_slice(devaddr);
        buffer.extend_from_slice(&fcnt.to_be_bytes());
        buffer.extend_from_slice(&dh_pub_id.to_be_bytes());
        buffer.extend_from_slice(ciphertext);

        buffer
    }


}

pub fn deserialize(input: &[u8]) -> Option<PhyPayload> {
    use nom::{Finish, Parser};

    fn parse_array<const N: usize>(input: &[u8]) -> nom::IResult<&[u8], [u8; N]> {
        nom::bytes::complete::take(N)
            .map(|data: &[u8]| data.try_into().unwrap())
            .parse(input)
    }

    match nom::combinator::complete(
        nom::sequence::tuple((
            nom::number::complete::be_u8,
            parse_array,
            parse_array,
            nom::number::complete::be_u16,
            nom::number::complete::be_u16,
            nom::combinator::rest.map(Vec::from),
        ))
        .map(|(mtype,nonce, devaddr,fcnt, dh_pub_id, ciphertext)| PhyPayload {
            mtype,
            nonce,
            devaddr,
            fcnt,
            dh_pub_id,
            ciphertext,
        }),
    )
    .parse(input)
    .finish()
    .map(|(_, header)| header) {
        Ok(x) => return Some(x),
        _=> return None,
    }
}