use rand_core::OsRng;

use twoRatchet::AS::ASRatchet;
use twoRatchet::ED::EDRatchet;
extern crate alloc;

fn main() {
    // handshake is finished, sk is the finished output that the two parties share
    let sk = [
        16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29,
        68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207,
    ];
    let downlink = [
        0, 171, 247, 26, 19, 92, 119, 193, 156, 216, 49, 89, 90, 174, 165, 23, 124, 247, 30, 79,
        73, 164, 55, 63, 178, 39, 228, 26, 180, 224, 173, 104,
    ];
    let uplink = [
        218, 132, 151, 66, 151, 72, 196, 104, 152, 13, 117, 94, 224, 7, 231, 216, 62, 155, 135, 52,
        59, 100, 217, 236, 115, 100, 161, 95, 8, 146, 123, 146,
    ];

    // devaddr, which is generated by AS
    let devaddr = [1, 2, 3, 2];

    // Using the output from handshake, the two parites initialize

    let mut ed_ratchet = EDRatchet::new(sk, downlink, uplink, devaddr, OsRng);

    let mut as_ratchet = ASRatchet::new(sk, uplink, downlink, devaddr, OsRng);

    let _newpk = ed_ratchet.initiate_ratch();

    let enci = ed_ratchet.ratchet_encrypt_payload(&b"msg".to_vec());

    let dec0 = match as_ratchet.receive(enci) {
        Ok((x, _b)) => x,
        Err(s) => panic!("decrpytion error {}", s),
    };

    assert_eq!(dec0, b"msg".to_vec());

    let otherpk = ed_ratchet.initiate_ratch();
    // R recevies dhr res
    let dh_ack = match as_ratchet.receive(otherpk) {
        Ok((x, _b)) => x,
        Err(s) => panic!("decrypt error {}", s), // in this case, do nothing
    };
    println!("acklen {}", dh_ack.len());

    match ed_ratchet.receive(dh_ack) {
        Ok(_x) => println!("succesfull ratch"),
        Err(s) => panic!("rathcet error {}", s),
    }
    // A test where a message is encrpyted, and a ratcheting procedure is performed 10 times.

    let enci = ed_ratchet.ratchet_encrypt_payload(&b"msg".to_vec());

    let dec0 = match as_ratchet.receive(enci) {
        Ok((x, _b)) => x,
        Err(_s) => [0].to_vec(),
    };

    assert_eq!(dec0, b"msg".to_vec());

    for n in 1..20 {
        let enci = ed_ratchet.ratchet_encrypt_payload(&b"msg".to_vec());

        let dec0 = match as_ratchet.receive(enci) {
            Ok((x, _b)) => x,
            Err(s) => panic!("error {}", s),
        };

        assert_eq!(dec0, b"msg".to_vec());

        let newpk = ed_ratchet.initiate_ratch();
        // R recevies dhr res
        if n % 2 == 0 {
            let dh_ack = match as_ratchet.receive(newpk) {
                Ok((x, _b)) => x,
                Err(s) => panic!("error {}", s),
            };

            let _ratchdone = ed_ratchet.receive(dh_ack);
        }
    }
}
