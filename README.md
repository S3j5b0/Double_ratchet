# Double_ratchet
attempted implementation of the double ratcheting algorithm, with DH procedure only happening once in a while, defined by some parameter. The  naming of fields and structs are made to comply with the LoRaRatchet protocol, such that it can be integrated into a LoRaWAN context.


Basic usage:

The repository consists of two parties, the `ED` and the `AS`>



```
    use rand_core::OsRng;

    use doubleratchet::r#as::ASRatchet;
    use doubleratchet::ed::EDRatchet;
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

    let devaddr = [1, 2, 3, 2];


    let mut ed_ratchet = EDRatchet::new(sk, downlink, uplink, devaddr, OsRng);

    let mut as_ratchet = ASRatchet::new(sk, uplink, downlink, devaddr, OsRng);
```
The above code initializes the two parties withtheir shared root key, sending chain key, and receiving chain key. The caller also needs to supply a devvaddr, which is a sort of connection identifier, and some implementation of a rng, that implements `RngCore` and `CryptoRng` 

Once this is done, both parties can encrypt and decrpyt messages. Receiving messages can be handled by calling the `receive` functions, which may fail in the case of a decrpytion or deserialization error. It also returns a boolean `b` indicating whether the returned value should be sent back to the ED.

```
    let enc0 = ed_ratchet.ratchet_encrypt_payload(b"msg");

    let dec0 = match as_ratchet.receive(enci) {
        Ok((x, _b)) => x,
        Err(s) => panic!("error unpacking {}", s),
    };

```

The ED can initialize a ratcheting step:

```
    let dhr_req = ed_ratchet.initiate_ratch();
    let dh_ack = match as_ratchet.receive(dhr_req) {
        Ok((x, _b)) => x,
        Err(s) => panic!("decrypt error {}", s), 
    };

    match ed_ratchet.receive(dh_ack) {
        Ok(_x) => println!("succesfull ratch"),
        Err(s) => panic!("rathcet error {}", s),
    }
```
THe ED initiates the ratchet, which is received by the AS, who sends back the value it ouputs from it's receive function.
