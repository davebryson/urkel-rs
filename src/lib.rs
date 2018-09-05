extern crate tiny_keccak;

pub mod hashutils;
pub mod proof;
pub mod tree;

#[cfg(test)]
mod tests {
    use hashutils::sha3;
    use proof::ProofType;
    use tree::MerkleTree;

    #[test]
    fn should_insert_and_get() {
        let mut t = MerkleTree::new();
        let key1 = sha3(b"name-1");
        let key2 = sha3(b"name-2");
        t.insert(key1, Vec::from("value-1"));
        t.insert(key2, Vec::from("value-2"));
        let rootHash = t.get_root();

        assert_eq!(
            "0xe027af0341702c08c4cba55912b0d57be8169a3cf78b3a46d71b0fba8493af57",
            format!("{:x}", rootHash)
        );

        assert_eq!(t.get(key1), Some(Vec::from("value-1")));
        assert_eq!(t.get(key2), Some(Vec::from("value-2")));

        let prf = t.prove(key2);
        let pv = prf.clone();

        assert!(prf.is_some());

        let pt = prf.unwrap();
        let result = match pt.proof_type {
            ProofType::Exists => true,
            _ => false,
        };
        assert!(result);

        let verified = match pv {
            Some(mut prf) => match prf.verify(rootHash, key1, 256) {
                Ok(_) => true,
                _ => false,
            },
            _ => false,
        };
        assert!(verified);

        let noproof = t.prove(sha3(b"Doesn't exist"));
        assert!(noproof.is_some());

        let works = match noproof {
            Some(v) => {
                if v.proof_type == ProofType::Collision {
                    true
                } else {
                    false
                }
            }
            _ => false,
        };

        assert!(works);
    }

    #[test]
    fn should_handle_get_on_nullnode() {
        let t = MerkleTree::new();
        assert_eq!(t.get(sha3(b"name-2")), None);
    }

}
