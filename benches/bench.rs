use criterion::{ criterion_group, criterion_main, BatchSize, Criterion,black_box};
use rand_core::OsRng;
use doubleratchet::r#as::ASRatchet;
use doubleratchet::ed::EDRatchet;

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

fn edhoc_detailed(c: &mut Criterion) {



    
    let mut group = c.benchmark_group("double_ratchet_detailed");


    group.bench_function("ed_build", |b| {
        b.iter(|| {
            EDRatchet::new(SK, UPLINK,DOWNLINK, DEVADDR, OsRng);
        })
    });
    
    group.bench_function("as_build", |b| {
        b.iter(|| {
            ASRatchet::new(SK, UPLINK, DOWNLINK, DEVADDR, OsRng);
        })
    });


    group.bench_function("ed_encrypt", |b| {
        b.iter_batched(
            || {
                let ed_ratchet = EDRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                ed_ratchet
            },
            |mut ed_ratchet| ed_ratchet.ratchet_encrypt_payload(b"Message"),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("as_encrypt", |b| {
        b.iter_batched(
            || {
                let as_ratchet = ASRatchet::new(SK, UPLINK,DOWNLINK, DEVADDR, OsRng);
                as_ratchet
            },
            |mut as_ratchet| as_ratchet.ratchet_encrypt_payload(b"Message"),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ed_decrypt", |b| {
        b.iter_batched(
            || {
                let ed_ratchet = EDRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let mut as_ratchet = ASRatchet::new(SK, UPLINK, DOWNLINK, DEVADDR, OsRng);
                let ciphertext = as_ratchet.ratchet_encrypt_payload(b"Message");
                (ed_ratchet,ciphertext)
            },
            |(mut ed_ratchet, ciphertext)| ed_ratchet.receive(ciphertext).unwrap(),
            BatchSize::SmallInput,
        )
    });


    group.bench_function("as_decrypt", |b| {
        b.iter_batched(
            || {
                let  as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let mut ed_ratchet = EDRatchet::new(SK, UPLINK,DOWNLINK, DEVADDR, OsRng);
                
                let ciphertext = ed_ratchet.ratchet_encrypt_payload(b"Message");
                (as_ratchet,ciphertext)
            },
            |(mut as_ratchet, ciphertext)| as_ratchet.receive(ciphertext).unwrap(),
            BatchSize::SmallInput,
        )
    });


    // decrypt for begge sider

    group.bench_function("ed_initiate_ratch", |b| {
        b.iter_batched(
            || {
                let ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
                ed_ratchet
            },
            |mut ed_ratchet| ed_ratchet.initiate_ratch(),
            BatchSize::SmallInput,
        )
    });


    group.bench_function("as_ratch", |b| {
        b.iter_batched(
            || {
                let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
                let  as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let dhr_req = ed_ratchet.initiate_ratch();
                (as_ratchet, dhr_req)
            },
            |(mut as_ratchet, dhr_req)| as_ratchet.receive(dhr_req).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ed_finalize", |b| {
        b.iter_batched(
            || {
                let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
                let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let dhr_req = ed_ratchet.initiate_ratch();
                let dhr_ack = as_ratchet.receive(dhr_req).unwrap().0;
                (ed_ratchet, dhr_ack)
            },
            |(mut ed_ratchet, dhr_ack)| ed_ratchet.receive(dhr_ack).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("as_finalize", |b| {
        b.iter_batched(
            || {
                let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
                let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let dhr_req = ed_ratchet.initiate_ratch();
                let dhr_ack = as_ratchet.receive(dhr_req).unwrap().0;
                let _none = ed_ratchet.receive(dhr_ack).unwrap();
                let uplink_ack = ed_ratchet.ratchet_encrypt_payload(b"Message");
                (as_ratchet, uplink_ack)
            },
            |(mut as_ratchet, uplink_ack)| as_ratchet.receive(uplink_ack).unwrap(),
            BatchSize::SmallInput,
        )
    });



    group.bench_function("ed_skip1", |b| {
        b.iter_batched(
            || {
                let ed_ratchet = EDRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let mut as_ratchet = ASRatchet::new(SK, UPLINK, DOWNLINK, DEVADDR, OsRng);
                let _skip_message = as_ratchet.ratchet_encrypt_payload(b"skipMessage");
                let ciphertext = as_ratchet.ratchet_encrypt_payload(b"Message");
                (ed_ratchet,ciphertext)
            },
            |(mut ed_ratchet, ciphertext)| ed_ratchet.receive(ciphertext).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("as_skip1", |b| {
        b.iter_batched(
            || {
                let mut ed_ratchet = EDRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let as_ratchet = ASRatchet::new(SK, UPLINK, DOWNLINK, DEVADDR, OsRng);
                let _skip_message = ed_ratchet.ratchet_encrypt_payload(b"skipMessage");
                let ciphertext = ed_ratchet.ratchet_encrypt_payload(b"Message");
                (as_ratchet,ciphertext)
            },
            |(mut as_ratchet, ciphertext)| as_ratchet.receive(ciphertext).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("ed_old_dhrp", |b| {
        b.iter_batched(
            || {
                let mut ed_ratchet = EDRatchet::new(SK,UPLINK,DOWNLINK, DEVADDR, OsRng);
                let mut as_ratchet = ASRatchet::new(SK, DOWNLINK, UPLINK, DEVADDR, OsRng);
                let old_message = as_ratchet.ratchet_encrypt_payload(b"lostMessage");
                let dhr_req = ed_ratchet.initiate_ratch();
                let dhr_ack = as_ratchet.receive(dhr_req).unwrap().0;
                let none = ed_ratchet.receive(dhr_ack).unwrap();
                assert_eq!(none,None);
                let uplink_ack = ed_ratchet.ratchet_encrypt_payload(b"uplinkAck");
                let _decrpyted_msg = as_ratchet.receive(uplink_ack).unwrap();
                (ed_ratchet,old_message)
            },
            |(mut ed_ratchet, old_message)| ed_ratchet.receive(old_message).unwrap(),
            BatchSize::SmallInput,
        )
    });



}



criterion_group!(edhoc_benches, edhoc_detailed);
criterion_main!(edhoc_benches);
