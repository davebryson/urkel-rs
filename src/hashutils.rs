use std::fmt;
use tiny_keccak::Keccak;

const LEAF_PREFIX: u8 = 0x00u8;
const INTERNAL_PREFIX: u8 = 0x01u8;

/// Container for a Hash
#[derive(Eq, PartialEq, PartialOrd, Debug, Clone, Copy)]
pub struct Digest(pub [u8; 32]);

/// Default returns a zero hash - used as a sentinal marker
impl Default for Digest {
    fn default() -> Digest {
        Digest([0; 32])
    }
}

/// Convert from &[u8] to Digest
impl<'a> From<&'a [u8]> for Digest {
    fn from(val: &'a [u8]) -> Self {
        let mut a = [0u8; 32];
        a.clone_from_slice(val);
        Digest(a)
    }
}

/// Display as lowercase hex string
impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0[0..32] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Hash of the content
pub fn sha3(data: &[u8]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];
    hash.update(&data);
    hash.finalize(&mut res);
    Digest(res)
}

/// Hash a leaf's key/values
pub fn sha3_leaf(key: Digest, value: &[u8]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    hash.update(&[LEAF_PREFIX]);
    hash.update(&key.0);
    hash.update(value);
    hash.finalize(&mut res);
    Digest(res)
}

/// Hash a leaf's k/v into the node's representation
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

/// Hash an internal node
pub fn sha3_internal(left: Digest, right: Digest) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    hash.update(&[INTERNAL_PREFIX]);
    hash.update(&left.0);
    hash.update(&right.0);
    hash.finalize(&mut res);
    Digest(res)
}

/// Calculate the checksum for the metaroot.
/// NOTE: this returns a full 32byte hash, but the metaroot uses 20bytes
/// We chop it in the MetaEntry to simplify borrowing issues.
pub fn checksum(data: &[u8], meta_key: [u8; 32]) -> [u8; 32] {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];

    hash.update(data);
    hash.update(&meta_key);
    hash.finalize(&mut res);
    res
}
