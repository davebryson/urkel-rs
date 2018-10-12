extern crate byteorder;
extern crate rand;
extern crate tiny_keccak;

pub mod codec;
pub mod hashutils;
pub mod nodes;
pub mod proof;
pub mod store;

use hashutils::{sha3, sha3_value, Digest};
use nodes::Node;
use proof::{has_bit, Proof, ProofType};
use store::Store;

/// Base-2 Merkle Tree
#[derive(Default)]
pub struct UrkelTree<'a> {
    /// Root Node
    root: Option<Node<'a>>,
    /// Size in bits of the digest
    keysize: usize,
    store: Store,
}

impl<'a> UrkelTree<'a> {
    pub fn new() -> Self {
        UrkelTree {
            root: Some(Node::empty()),
            keysize: 256,
            store: Default::default(),
        }
    }

    pub fn get_root(&self) -> Digest {
        // TODO: Clean this up
        let r = self.root.as_ref().expect("Node root was None");
        r.hash()
    }

    pub fn insert(&mut self, nkey: Digest, value: &'a [u8]) {
        let mut depth = 0;
        let mut to_hash = Vec::<Node>::new();
        let leaf_hash = sha3_value(nkey, value);

        let mut root = self.root.take().unwrap();

        loop {
            match root {
                Node::Empty {} => break,
                Node::Hash { index, pos, .. } => {
                    root = self.store.resolve(index, pos, root.is_leaf());
                }
                Node::Leaf {
                    key, value, hash, ..
                } => {
                    if nkey == key {
                        if leaf_hash == hash {
                            self.root = Some(root);
                            //return Some(root);
                            return;
                        }
                        break;
                    }

                    while has_bit(&nkey, depth) == has_bit(&key, depth) {
                        to_hash.push(Node::Empty {});
                        depth += 1;
                    }

                    to_hash.push(Node::leaf(key, value));

                    depth += 1;
                    break;
                }
                Node::Internal { left, right, .. } => {
                    if depth == self.keysize {
                        panic!("Missing node at depth {}", depth);
                    }

                    if has_bit(&nkey, depth) {
                        to_hash.push(*left);
                        root = *right;
                    } else {
                        to_hash.push(*right);
                        root = *left
                    }
                    depth += 1;
                }
            }
        }

        // Start with a leaf of the new values
        let mut new_root = Node::Leaf {
            pos: 0,
            index: 0,
            hash: leaf_hash,
            key: nkey,
            value: Some(value),
            vindex: 0,
            vpos: 0,
            vsize: 0,
        };

        // Walk the tree bottom up to form the new root
        for n in to_hash.into_iter().rev() {
            depth -= 1;
            if has_bit(&nkey, depth) {
                new_root = Node::Internal {
                    left: Box::new(n),
                    right: Box::new(new_root),
                    index: 0,
                    pos: 0,
                    hash: Default::default(),
                };
            } else {
                new_root = Node::Internal {
                    left: Box::new(new_root),
                    right: Box::new(n),
                    index: 0,
                    pos: 0,
                    hash: Default::default(),
                };
            }
        }

        self.root = Some(new_root);
        //Some(new_root)
    }

    pub fn get(&mut self, nkey: Digest) -> Option<Vec<u8>> {
        let mut depth = 0;
        let mut current = self.root.clone().unwrap();
        loop {
            match current {
                Node::Leaf {
                    key,
                    value,
                    vindex,
                    vpos,
                    vsize,
                    ..
                } => {
                    if nkey != key {
                        return None;
                    }
                    if value.is_some() {
                        return value.and_then(|v| Some(Vec::from(v)));
                    }

                    // TODO: This needs refactored
                    return Some(self.store.retrieve(vindex, vpos, vsize));
                }
                Node::Internal { left, right, .. } => {
                    if has_bit(&nkey, depth) {
                        current = *right;
                    } else {
                        current = *left;
                    }
                    depth += 1;
                }
                Node::Hash { index, pos, .. } => {
                    let is_leaf = current.is_leaf();
                    current = self.store.resolve(index, pos, is_leaf);
                }
                _ => return None,
            }
        }
    }

    pub fn prove(&mut self, nkey: Digest) -> Option<Proof> {
        let mut depth = 0;
        let mut proof = Proof::default();

        let keysize = self.keysize;
        let mut current = self.root.clone().unwrap();
        loop {
            match current {
                Node::Empty {} => break,
                Node::Hash { index, pos, .. } => {
                    let is_leaf = current.is_leaf();
                    current = self.store.resolve(index, pos, is_leaf);
                }
                Node::Internal { left, right, .. } => {
                    if depth == keysize {
                        panic!("Missing node at depth {}", depth);
                    }

                    if has_bit(&nkey, depth) {
                        proof.push(left.hash());
                        current = *right;
                    } else {
                        proof.push(right.hash());
                        current = *left;
                    }

                    depth += 1;
                }
                Node::Leaf {
                    key,
                    vindex,
                    vpos,
                    vsize,
                    ..
                } => {
                    let val = self.store.retrieve(vindex, vpos, vsize);

                    if nkey == key {
                        proof.proof_type = ProofType::Exists;
                        proof.value = Some(val);
                    } else {
                        proof.proof_type = ProofType::Collision;
                        proof.key = Some(key);
                        //proof.hash = Some(val.map(|v| sha3(v)).unwrap());
                        proof.hash = Some(sha3(&val));
                    }
                    break;
                }
            }
        }

        Some(proof)
    }

    // Commit subtree to storage and set a new Hashnode root.
    pub fn commit(&mut self) {
        // newroot is a node::hash
        let newroot = self.root.take().map(|t| self.write(t));
        println!("Got the new root: {:?}", newroot);
        self.store.commit();
        // Write to meta
        //self.store.commit(&newroot);
        self.root = newroot;
    }

    fn write(&mut self, mut node: Node<'a>) -> Node<'a> {
        match node {
            Node::Empty {} => Node::empty(),
            Node::Internal {
                pos,
                index,
                hash,
                left,
                right,
            } => {
                // Go left recursively
                let left_result = self.write(*left);
                // ...then right
                let right_result = self.write(*right);

                // Now construct a new entry
                let mut tempnode = Node::Internal {
                    pos,
                    index,
                    hash,
                    left: Box::new(left_result),
                    right: Box::new(right_result),
                };

                // Calc hash for the hashnode
                let hashed = tempnode.hash();

                // Only store if we haven't already
                if index == 0 {
                    self.store.write_node(&mut tempnode);
                }

                let (newindex, newpos, _) = tempnode.get_info();

                // Now it *should* be stored
                assert!(!tempnode.should_save(), "Didn't persist the node");

                //let (newindex, newpos, _) = tempnode.get_info();

                Node::Hash {
                    pos: newpos,
                    index: newindex,
                    hash: hashed,
                }
            }
            Node::Leaf { .. } => {
                // Write the value for the leaf node...
                // ...then the node itself
                self.store.write_value(&mut node);
                self.store.write_node(&mut node);

                // the index should be set!
                assert!(!node.should_save(), "Didn't persist the node");

                // TODO: Cleanup aisle 5
                // get the updated index/pos
                let (newindex, newpos, _) = node.get_info();
                let hashed = node.hash();
                Node::Hash {
                    pos: newpos,
                    index: newindex,
                    hash: hashed,
                }
            }
            Node::Hash { .. } => {
                assert!(!node.should_save());
                node
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_basics() {
        let mut t = UrkelTree::new();
        let key1 = sha3(b"name-1");
        let key2 = sha3(b"name-2");

        t.insert(key1, b"value-1");

        for i in 3..40 {
            let k = sha3(format!("name-{}", i).as_bytes());
            t.insert(k, &[2u8; 20]);
        }

        t.insert(key2, b"value-2");

        t.commit();

        assert_eq!(t.get(key1), Some(Vec::from("value-1")));
        assert_eq!(t.get(key2), Some(Vec::from("value-2")));

        // Test good proof
        let prf = t.prove(key2);
        assert!(prf.is_some());
        if let Some(pt) = prf {
            assert!(pt.proof_type == ProofType::Exists);
            assert!(pt.value == Some(Vec::from("value-2")));
        }

        // Test deadend (doesn't exist)
        let noproof = t.prove(sha3(b"doesn't exist"));
        assert!(noproof.is_some());
        if let Some(np) = noproof {
            assert!(np.proof_type == ProofType::Deadend);
            assert!(np.key.is_none());
        }
    }
}
