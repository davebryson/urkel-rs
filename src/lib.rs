extern crate sha2;
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

        assert_eq!(
            "0xb86805a796ed09229c23b327537e450bec57b43e9946455fc5e859345adf1abd",
            format!("{:x}", t.get_root())
        );

        assert_eq!(t.get(key1), Some(Vec::from("value-1")));
        assert_eq!(t.get(key2), Some(Vec::from("value-2")));

        // Test good proof
        let prf = t.prove(key2);
        assert!(prf.is_some());
        if let Some(pt) = prf {
            assert!(pt.proof_type == ProofType::Exists);
            assert!(pt.value == Some(Vec::from("value-2")));
        }

        // Test collision
        let noproof = t.prove(sha3(b"Doesn't exist"));
        assert!(noproof.is_some());
        if let Some(np) = noproof {
            assert!(np.proof_type == ProofType::Collision);
            assert!(np.key.is_some());
            assert!(np.hash.is_some());
        }
    }

    #[test]
    fn should_handle_get_on_nullnode() {
        let t = MerkleTree::new();
        assert_eq!(t.get(sha3(b"name-2")), None);
    }

    #[test]
    fn should_verify() {
        let mut t = MerkleTree::new();
        let key1 = sha3(b"name-1");
        let key2 = sha3(b"name-2");
        t.insert(key1, Vec::from("value-1"));
        t.insert(key2, Vec::from("value-2"));

        let prf = t.prove(key2);
        assert!(prf.is_some());

        if let Some(mut p) = prf {
            let r = p.verify(t.get_root(), key2, 256);
            assert!(r.is_ok());
        }
    }

}
