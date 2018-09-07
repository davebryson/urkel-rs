use hashutils::{sha3_internal, sha3_leaf, sha3_value, sha3_zero_hash, Digest};
use tree::has_bit;

#[derive(Eq, PartialEq, Clone)]
pub enum ProofType {
    Exists,
    Collision,
    Deadend,
}

#[derive(Eq, PartialEq, Clone)]
pub struct Proof {
    pub proof_type: ProofType,
    node_hashes: Vec<Digest>,
    pub key: Option<Digest>,
    pub hash: Option<Digest>,
    pub value: Option<Vec<u8>>,
}

impl Proof {
    // Default Proof (deadend)
    pub fn new() -> Self {
        Proof {
            proof_type: ProofType::Deadend,
            node_hashes: Vec::<Digest>::new(),
            key: None,
            hash: None,
            value: None,
        }
    }

    pub fn depth(&self) -> usize {
        self.node_hashes.len()
    }

    pub fn push(&mut self, hash: Digest) {
        self.node_hashes.push(hash);
    }

    pub fn is_sane(&self, bits: usize) -> bool {
        let result = match self.proof_type {
            ProofType::Exists => {
                if self.key.is_some() {
                    false
                } else if self.hash.is_some() {
                    false
                } else if self.value.is_none() {
                    false
                } else if self.value.as_ref().unwrap().len() > 0xffff {
                    false
                } else {
                    true
                }
            }
            ProofType::Collision => {
                if self.key.is_none() {
                    false
                } else if self.hash.is_none() {
                    false
                } else if self.value.is_some() {
                    false
                } else if self.key.as_ref().unwrap().0.len() != (bits >> 3) {
                    false
                } else if self.hash.as_ref().unwrap().0.len() != 32 {
                    false
                } else {
                    true
                }
            }
            ProofType::Deadend => false,
        };
        result
    }

    pub fn verify(
        &mut self,
        root_hash: Digest,
        key: Digest,
        bits: usize,
    ) -> Result<Vec<u8>, &'static str> {
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
                sha3_value(key, v.as_slice())
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
