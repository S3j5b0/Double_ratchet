use x25519_dalek_ng::{PublicKey,StaticSecret, SharedSecret};

use rand_core::{OsRng,};

use twoRatchet::ratchfuncs::{state};

use ccm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    consts::{U13, U8},
    Ccm,
};

fn main() {
    //// TODO:
    /// make error handling for aead decrpyiton



    // handshake is finished, sk is the finished output that the two parties share
    let sk = [16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29, 68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207];
    let downlink = [0, 171, 247, 26, 19, 92, 119, 193, 156, 216, 49, 89, 90, 174, 165, 23, 124, 247, 30, 79, 73, 164, 55, 63, 178, 39, 228, 26, 180, 224, 173, 104];
    let uplink = [218, 132, 151, 66, 151, 72, 196, 104, 152, 13, 117, 94, 224, 7, 231, 216, 62, 155, 135, 52, 59, 100, 217, 236, 115, 100, 161, 95, 8, 146, 123, 146];
    
    
    let ad_r = &[1];
    let ad_i = &[2];

    // iFirst the two parties initialize, where I outputs her pk

    let(mut i_ratchet, dhr_req)  = state::init_i(sk,downlink, uplink,ad_i.to_vec(), ad_r.to_vec());

    let mut r_ratchet = state::init_r(sk, uplink,downlink, ad_i.to_vec(), ad_r.to_vec());



    // r recevies the pk of i, ratcets, and sends it's own pk
/*
    let newout = match  r_ratchet.r_receive(dhr_req) {
        Some((x,b)) => x,
        None => [0].to_vec(), // in this case, do nothing
    };

    // i receives the pk of r, and makes it's own ratchet
    let _ratchdone =  i_ratchet.i_receive(newout); 



    // Now we are both fully initialized with a ratchet, and I should be able to encrypt something
    let enclost = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);
*/
    let enc0 = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);


    let dec0 = match r_ratchet.r_receive(enc0){
        Some((x,b)) => x,
        None => [0].to_vec(),
    };

    assert_eq!(dec0, b"lost".to_vec());

    let encr = r_ratchet.ratchet_encrypt(&b"downlink".to_vec(), ad_r);


    let decr = match i_ratchet.i_receive(encr){
        Some((x,b)) => x,
        None => [0].to_vec(), // do nothing
    };



    // now I wants to ratchet again

   let newpk = i_ratchet.i_initiate_ratch();

    // R recevies dhr res
    let dh_ack = match  r_ratchet.r_receive(newpk) {
        Some((x,b)) => x,
        None => [0].to_vec(), // in this case, do nothing
    }; 
    // and responds with a dhr ack, which i receives
    let _ratchdone =  i_ratchet.i_receive(dh_ack); 

    let lostmsg = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);
    let msg3 = i_ratchet.ratchet_encrypt(&b"msg3".to_vec(), ad_i);


    let dec0 = match r_ratchet.r_receive(msg3){
        Some((x,b)) => x,
        None => [0].to_vec(),
    };

    assert_eq!(b"msg3".to_vec(),dec0);
    let declost = match r_ratchet.r_receive(lostmsg){
        Some((x,b)) => x,
        None => [0].to_vec(),
    };
    assert_eq!(b"msg3".to_vec(),dec0);





/*

// now r will send this pk to I

*/

    
}



 

