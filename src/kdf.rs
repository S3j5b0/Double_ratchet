use hkdf::Hkdf;
use sha2::Sha256;


pub fn kdf_rk(salt: [u8;32],  input: &[u8]) -> ([u8;32],[u8;32]) {
    
    let mut output = [0u8; 64];

    let h = Hkdf::<Sha256>::new(Some(&salt),input);

    h.expand(b"ConstantIn", &mut output).unwrap();

    let (rk,ck) = output.split_at(32);
    
    (rk.try_into().unwrap(),ck.try_into().unwrap())
}

pub fn kdf_ck(input: &[u8]) -> ([u8;32],[u8;32]) {
    let mut output = [0u8; 64];
    // kdf_ck should have a constant 
    let salt = &[1;32];
    let h = Hkdf::<Sha256>::new(Some(salt),input);

    h.expand(b"ConstantIn", &mut output).unwrap();

    let (rk,ck) = output.split_at(32);

    (rk.try_into().unwrap(),ck.try_into().unwrap())
}



