use std::fmt;
use tiny_keccak::Keccak;

const LEAF_PREFIX: u8 = 0x00u8;
const INTERNAL_PREFIX: u8 = 0x01u8;

#[derive(Eq, PartialEq, PartialOrd, Debug, Clone, Copy)]
pub struct Digest(pub [u8; 32]);

impl Default for Digest {
    fn default() -> Digest {
        Digest([0; 32])
    }
}

impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0[0..32] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub fn sha3(data: &[u8]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];
    hash.update(&data);
    hash.finalize(&mut res);
    Digest(res)
}

pub fn sha3_leaf(key: Digest, value: &[u8]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    hash.update(&[LEAF_PREFIX]);
    hash.update(&key.0);
    hash.update(value);
    hash.finalize(&mut res);
    Digest(res)
}

pub fn sha3_value(key: Digest, value: &[u8]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    let val = sha3(value);
    hash.update(&[LEAF_PREFIX]);
    hash.update(&key.0);
    hash.update(&val.0);
    hash.finalize(&mut res);
    Digest(res)
}

pub fn sha3_internal(left: Digest, right: Digest) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    hash.update(&[INTERNAL_PREFIX]);
    hash.update(&left.0);
    hash.update(&right.0);
    hash.finalize(&mut res);
    Digest(res)
}

pub fn sha3_zero_hash() -> Digest {
    Digest([0; 32])
}
