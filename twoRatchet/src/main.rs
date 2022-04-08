

use twoRatchet::ratchfuncs::{State};
extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
struct SomeNum {
    id: u16,
    n: u16,
}
fn main() {


    let mut map: BTreeMap<(u16,u16), [u8;32]> = BTreeMap::new();
    
    let n : u16 = 10;
    let h : u16 = 16;

    let bb: Vec<u8> = [n.to_be_bytes(), h.to_be_bytes()].concat();



    // handshake is finished, sk is the finished output that the two parties share
    let sk = [16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29, 68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207];
    let downlink = [0, 171, 247, 26, 19, 92, 119, 193, 156, 216, 49, 89, 90, 174, 165, 23, 124, 247, 30, 79, 73, 164, 55, 63, 178, 39, 228, 26, 180, 224, 173, 104];
    let uplink = [218, 132, 151, 66, 151, 72, 196, 104, 152, 13, 117, 94, 224, 7, 231, 216, 62, 155, 135, 52, 59, 100, 217, 236, 115, 100, 161, 95, 8, 146, 123, 146];
    
    
    let devaddr = &[1,2,3,2];

    // iFirst the two parties initialize, where I outputs her pk

    let mut i_ratchet  = State::init_i(sk,downlink, uplink,devaddr.to_vec());

    let mut r_ratchet = State::init_r(sk, uplink,downlink, devaddr.to_vec());




for i in 1..10 {

    let enc0 = i_ratchet.ratchet_encrypt_payload(&b"lost".to_vec(), devaddr);


    let dec0 = match r_ratchet.r_receive(enc0){
        Some((x,b)) => x,
        None => [0].to_vec(),
    };

    assert_eq!(dec0, b"lost".to_vec());


    if i_ratchet.fcnt_send >= 3 {
    let newpk = i_ratchet.i_initiate_ratch();
    // R recevies dhr res
    let dh_ack = match  r_ratchet.r_receive(newpk) {
        Some((x,b)) => x,
        None => [0].to_vec(), // in this case, do nothing
    };    

    let _ratchdone =  i_ratchet.i_receive(dh_ack); 
}
}





 
    

    
}



 

