extern crate tiny_keccak;

pub mod hashutils;
pub mod memorydb;
pub mod nodes;
pub mod proof;
pub mod store;

use hashutils::{sha3, sha3_value, Digest};
use memorydb::MemoryDb;
use nodes::{Node, NodeStore};
use proof::{has_bit, Proof, ProofType};

/// Base-2 Merkle Tree
pub struct UrkelTree {
    /// Root Node
    root: Option<Node>,
    /// Size in bits of the digest
    keysize: usize,
    /// Persistent Store
    store: MemoryDb,
}

impl Default for UrkelTree {
    fn default() -> Self {
        UrkelTree {
            root: Some(Node::empty()),
            keysize: 256,
            store: Default::default(),
        }
    }
}

impl UrkelTree {
    pub fn get_root(&self) -> Digest {
        let r = self.root.as_ref().expect("Node root was None");
        r.hash()
    }

    pub fn insert(&mut self, nkey: Digest, value: Vec<u8>) {
        let newroot = self
            .root
            .take()
            .map(|t| do_insert(t, self.keysize, nkey, value));
        self.root = newroot;
    }

    pub fn get(&self, nkey: Digest) -> Option<Vec<u8>> {
        let mut depth = 0;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Node::Leaf { key, value, .. } => {
                    if nkey != *key {
                        return None;
                    }
                    // TODO: if the current node has a value return it
                    // else pull from store
                    if !value.is_empty() {
                        return Some(value.to_vec());
                    }
                    return None;
                }
                Node::Internal { left, right, .. } => {
                    if has_bit(&nkey, depth) {
                        current = &*right;
                    } else {
                        current = &*left;
                    }
                    depth += 1;
                }
                Node::Hash { params } => {
                    if let Some(x) = self.store.get(params.data) {
                        current = x
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
    }

    pub fn prove(&self, nkey: Digest) -> Option<Proof> {
        let mut depth = 0;
        let mut proof = Proof::default();

        let keysize = self.keysize;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Node::Empty {} => break,
                Node::Hash { .. } => { /* TODO: should pull from store */ }
                Node::Internal { left, right, .. } => {
                    if depth == keysize {
                        panic!(format!("Missing node at depth {}", depth));
                    }

                    if has_bit(&nkey, depth) {
                        proof.push(left.hash());
                        current = &*right;
                    } else {
                        proof.push(right.hash());
                        current = &*left
                    }

                    depth += 1;
                }
                Node::Leaf { key, value, .. } => {
                    if nkey == *key {
                        proof.proof_type = ProofType::Exists;
                        proof.value = Some(value.to_vec());
                    } else {
                        proof.proof_type = ProofType::Collision;
                        proof.key = Some(*key);
                        proof.hash = Some(sha3(value.as_slice()));
                    }
                    break;
                }
            }
        }

        Some(proof)
    }

    // Commit subtree to storage and set a new Hashnode root.
    pub fn commit(&mut self) {
        let newroot = self.root.take().map(|t| self.write(t));
        self.root = newroot;
    }

    fn write(&mut self, n: Node) -> Node {
        match n {
            Node::Empty {} => Node::empty(),
            Node::Internal { left, right, .. } => {
                // Don't necessarily like the recursive call
                // but not sure of a better way to do it...
                let left_result = self.write(*left);
                let right_result = self.write(*right);

                let mut node = Node::Internal {
                    left: Box::new(left_result),
                    right: Box::new(right_result),
                    params: Default::default(),
                };

                println!("Store node {:x}", node.hash());
                self.store.put(node)
            }
            Node::Leaf {
                key, value, params, ..
            } => {
                // Store node
                //println!("Store leaf {:x}", n.hash());
                let l = Node::leaf(key, value.to_vec(), params);
                self.store.put(l)
            }
            Node::Hash { params } => Node::Hash { params },
        }
    }
}

/// Insert on the Tree
fn do_insert(mut root: Node, keysize: usize, nkey: Digest, value: Vec<u8>) -> Node {
    let mut depth = 0;
    let leaf_hash = sha3_value(nkey, value.as_slice());
    let mut to_hash = Vec::<Node>::new();

    loop {
        match root {
            Node::Empty {} => break,
            Node::Hash { .. } => { /*should pull from store*/ }
            Node::Leaf {
                key, value, params, ..
            } => {
                if nkey == key {
                    if leaf_hash == params.data {
                        return Node::leaf(key, value, params);
                    }
                    break;
                }

                while has_bit(&nkey, depth) == has_bit(&key, depth) {
                    to_hash.push(Node::Empty {});
                    depth += 1;
                }

                to_hash.push(Node::leaf(key, value, params));

                depth += 1;
                break;
            }
            Node::Internal { left, right, .. } => {
                if depth == keysize {
                    panic!(format!("Missing node at depth {}", depth));
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

    let params = NodeStore {
        data: leaf_hash,
        index: 0,
        flags: 0,
    };

    // Start with a leaf of the new values
    let mut new_root = Node::leaf(nkey, value, params);

    // Walk the tree bottom up to form the new root
    for n in to_hash.into_iter().rev() {
        depth -= 1;
        if has_bit(&nkey, depth) {
            new_root = Node::Internal {
                left: Box::new(n),
                right: Box::new(new_root),
                params: Default::default(),
            };
        } else {
            new_root = Node::Internal {
                left: Box::new(new_root),
                right: Box::new(n),
                params: Default::default(),
            };
        }
    }

    new_root
}
