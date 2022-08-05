
#[cfg(test)]


use doubleratchet::r#as::ASRatchet;
use doubleratchet::ed::EDRatchet;
use rand_core::OsRng;

pub const  SK : [u8;32] = [
    16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29,
    68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207,
];
pub const DOWNLINK : [u8;32] = [
    0, 171, 247, 26, 19, 92, 119, 193, 156, 216, 49, 89, 90, 174, 165, 23, 124, 247, 30, 79,
    73, 164, 55, 63, 178, 39, 228, 26, 180, 224, 173, 104,
];
pub const UPLINK : [u8;32] = [
    218, 132, 151, 66, 151, 72, 196, 104, 152, 13, 117, 94, 224, 7, 231, 216, 62, 155, 135, 52,
    59, 100, 217, 236, 115, 100, 161, 95, 8, 146, 123, 146,
];

pub const DEVADDR : [u8;4] = [1, 2, 3, 2];
#[test]

fn correctness() {
    let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
    let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);

    let ciphertext = ed_ratchet.ratchet_encrypt_payload(b"Message");

    let decrypedmessage = as_ratchet.receive(ciphertext).unwrap().0;
    assert_eq!(decrypedmessage,b"Message");

    let ciphertext2 = as_ratchet.ratchet_encrypt_payload(b"Message");


    let decrypedmessage2 = ed_ratchet.receive(ciphertext2).unwrap().unwrap();



    assert_eq!(decrypedmessage2,b"Message");
}

#[test]

fn message_loss() {
    let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
    let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);


    let _lost_ciphertext = ed_ratchet.ratchet_encrypt_payload(b"LostMessage");
    let ciphertext = ed_ratchet.ratchet_encrypt_payload(b"Message");

    let decrypedmessage = as_ratchet.receive(ciphertext).unwrap().0;
    assert_eq!(decrypedmessage,b"Message");

    let _ciphertext2 = as_ratchet.ratchet_encrypt_payload(b"LostMessage");
    let ciphertext2 = as_ratchet.ratchet_encrypt_payload(b"Message2");

    let decrypedmessage2 = ed_ratchet.receive(ciphertext2).unwrap().unwrap();

    assert_eq!(decrypedmessage2, b"Message2");
}




#[test]

fn dhrp() {
    let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
    let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);

    //  ENCRYPT
    let ciphertext0 = ed_ratchet.ratchet_encrypt_payload(b"Message");

    let decrypedmessage = as_ratchet.receive(ciphertext0).unwrap().0;
    assert_eq!(decrypedmessage,b"Message");

    // DHRP 
    let dhr_req = ed_ratchet.initiate_ratch();
    let dhr_ack = as_ratchet.receive(dhr_req).unwrap().0;

    let _ = ed_ratchet.receive(dhr_ack);
    let ack_uplink = ed_ratchet.ratchet_encrypt_payload(b"ackmessage");
    let uplink_ack_decrypted = as_ratchet.receive(ack_uplink).unwrap().0;

    assert_eq!(uplink_ack_decrypted, b"ackmessage");

    // Encrypt


    let ciphertext = ed_ratchet.ratchet_encrypt_payload(b"Message");

    let decrypedmessage = as_ratchet.receive(ciphertext).unwrap().0;
    assert_eq!(decrypedmessage,b"Message");



}