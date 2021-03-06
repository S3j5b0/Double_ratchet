extern crate alloc;

use alloc::vec::Vec;

pub struct PhyPayload {
    pub mtype: i8,
    pub nonce: [u8; 13],
    pub fcnt: u16, 
    pub devaddr : [u8;4],
    pub dh_pub_id: u16,
    pub ciphertext: Vec<u8>,
}

impl PhyPayload {
    pub fn new( mtype : i8,devaddr:[u8;4],fcnt: u16, dh_pub_id: u16, ciphertext: Vec<u8>,nonce :[u8;13]) -> Self {
        PhyPayload {
            mtype,
            nonce,
            devaddr,
            fcnt,
            dh_pub_id,
            ciphertext,
            
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

        let mut buffer = Vec::with_capacity(22+ciphertext.len());


        buffer.extend_from_slice(&mtype.to_be_bytes());
        buffer.extend_from_slice(nonce);
        buffer.extend_from_slice(devaddr);
        buffer.extend_from_slice(&fcnt.to_be_bytes());
        buffer.extend_from_slice(&dh_pub_id.to_be_bytes());
        buffer.extend_from_slice(ciphertext);

        buffer
    }


}

pub fn deserialize_phy(input: &[u8]) -> Result<PhyPayload, &'static str> {
    use nom::{Finish, Parser};

    fn parse_array<const N: usize>(input: &[u8]) -> nom::IResult<&[u8], [u8; N]> {
        nom::bytes::complete::take(N)
            .map(|data: &[u8]| data.try_into().unwrap())
            .parse(input)
    }

    match nom::combinator::complete(
        nom::sequence::tuple((
            nom::number::complete::be_i8,
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
        Ok(x) => Ok(x),
        Err(_)=> Err("failed to deserialize phypayload"),
    }
}

