extern crate tiny_keccak;

pub mod hashutils;
pub mod tree;

#[cfg(test)]
mod tests {
    use hashutils::sha3;
    use tree::MerkleTree;

    #[test]
    fn should_insert_and_get() {
        let mut t = MerkleTree::new();
        t.insert(sha3(b"name-1"), Vec::from("value-1"));
        t.insert(sha3(b"name-2"), Vec::from("value-2"));

        assert_eq!(
            "0xe027af0341702c08c4cba55912b0d57be8169a3cf78b3a46d71b0fba8493af57",
            format!("{:x}", t.get_root())
        );

        assert_eq!(t.get(sha3(b"name-1")), Some(Vec::from("value-1")));
        assert_eq!(t.get(sha3(b"name-2")), Some(Vec::from("value-2")));
    }
}
