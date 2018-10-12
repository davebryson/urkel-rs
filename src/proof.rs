use super::hashutils::{sha3_internal, sha3_leaf, sha3_value, sha3_zero_hash, Digest};

/// Determine which direction to go in the Tree based on the bit in the key
/// Used in the tree and Proof
pub fn has_bit(key: &Digest, index: usize) -> bool {
    let oct = index >> 3;
    let bit = index & 7;
    match (key.0[oct] >> (7 - bit)) & 1 {
        0 => false,
        1 => true,
        _ => false,
    }
}

#[derive(Eq, PartialEq, Clone)]
pub enum ProofType {
    Exists,
    Collision,
    Deadend,
}

#[derive(Eq, PartialEq, Clone)]
pub struct Proof<'a> {
    pub proof_type: ProofType,
    node_hashes: Vec<Digest>,
    pub key: Option<Digest>,
    pub hash: Option<Digest>,
    pub value: Option<&'a [u8]>,
}

impl<'a> Default for Proof<'a> {
    fn default() -> Self {
        Proof {
            proof_type: ProofType::Deadend,
            node_hashes: Vec::<Digest>::new(),
            key: None,
            hash: None,
            value: None,
        }
    }
}

impl<'a> Proof<'a> {
    pub fn depth(&self) -> usize {
        self.node_hashes.len()
    }

    pub fn push(&mut self, hash: Digest) {
        self.node_hashes.push(hash);
    }

    pub fn is_sane(&self, bits: usize) -> bool {
        match self.proof_type {
            ProofType::Exists => {
                !(self.key.is_some()
                    || self.hash.is_some()
                    || self.value.is_none()
                    || self.value.as_ref().unwrap().len() > 0xffff)
            }
            ProofType::Collision => {
                !(self.key.is_none()
                    || self.hash.is_none()
                    || self.value.is_some()
                    || self.key.as_ref().unwrap().0.len() != (bits >> 3)
                    || self.hash.as_ref().unwrap().0.len() != 32)
            }
            ProofType::Deadend => false,
        }
    }

    pub fn verify(
        &mut self,
        root_hash: Digest,
        key: Digest,
        bits: usize,
    ) -> Result<&'a [u8], &'static str> {
        if !self.is_sane(bits) {
            return Err("Unknown");
        }

        let leaf = match self.proof_type {
            ProofType::Deadend => sha3_zero_hash(), /*sha3(&[0; 32])*/
            ProofType::Collision => {
                if self.key == Some(key) {
                    return Err("Same Key");
                }
                let k = self.key.unwrap();
                let h = self.hash.unwrap();
                sha3_leaf(k, &h.0)
            }
            ProofType::Exists => {
                let v = self.value.as_ref().unwrap();
                sha3_value(key, v)
            }
        };

        let mut next = leaf;
        let mut depth = self.depth() - 1;

        for n in self.node_hashes.iter().rev() {
            if has_bit(&key, depth) {
                next = sha3_internal(*n, next)
            } else {
                next = sha3_internal(next, *n)
            }

            if depth > 0 {
                depth -= 1;
            }
        }

        if next != root_hash {
            Err("Head Mismatch")
        } else {
            self.value.take().ok_or("Bad Verification")
        }
    }
}
