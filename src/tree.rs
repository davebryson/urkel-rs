use super::Error;
use hashutils::{sha3, sha3_value, Digest};
use nodes::Node;
use proof::{has_bit, Proof, ProofType};
use store::Store;

/// Base-2 Merkle Trie
#[derive(Default)]
pub struct UrkelTree<'a> {
    /// Root Node
    root: Option<Node<'a>>,
    /// Size in bits of the digest
    keysize: usize,
    /// FF Store
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

    /// Return the root hash of the tree or zeros for None
    pub fn get_root(&self) -> Digest {
        self.root.as_ref().map_or(Digest::default(), |r| r.hash())
    }

    /// Insert a new key/value pair into the Tree
    pub fn insert(&mut self, nkey: Digest, value: &'a [u8]) {
        let mut depth = 0;
        let mut to_hash = Vec::<Node>::new();
        let leaf_hash = sha3_value(nkey, value);

        let mut root = self.root.take().unwrap();
        loop {
            match root {
                Node::Empty {} => break,
                Node::Hash { index, pos, .. } => {
                    // Reach back to storage and convert the hash node to a leaf or internal
                    root = self
                        .store
                        .resolve(index, pos, root.is_leaf())
                        .expect("Failed to resolve Hashnode");
                }
                Node::Leaf {
                    key, value, hash, ..
                } => {
                    if nkey == key {
                        if leaf_hash == hash {
                            self.root = Some(root);
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
                        panic!("Insert: missing node at depth {}", depth);
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

        // Start with a leaf of the new K/V
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
    }

    /// Get a value (if it exists) for a given key
    pub fn get(&mut self, nkey: Digest) -> Option<Vec<u8>> {
        let mut depth = 0;
        // Clone here to deal with borrowing issues for resolve().
        // If current is a ref, the return from 'resolve' has a lifetime
        // issue.  Ideally walking the tree should be ref...
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

                    match self.store.retrieve(vindex, vpos, vsize) {
                        Ok(v) => return Some(v),
                        _ => return None,
                    }
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
                    current = self
                        .store
                        .resolve(index, pos, is_leaf)
                        .expect("Failed to resolve Hashnode");
                }
                _ => return None,
            }
        }
    }

    /// Prove a key does/does not exist in the Tree
    pub fn prove(&mut self, nkey: Digest) -> Option<Proof> {
        let mut depth = 0;
        let mut proof = Proof::default();

        // Again the clone...same reason as get()
        let mut current = self.root.clone().unwrap();
        loop {
            match current {
                Node::Empty {} => break,
                Node::Hash { index, pos, .. } => {
                    let is_leaf = current.is_leaf();
                    current = self
                        .store
                        .resolve(index, pos, is_leaf)
                        .expect("Failed to resolve Hashnode");
                }
                Node::Internal { left, right, .. } => {
                    if depth == self.keysize {
                        panic!("Proof: missing node at depth {}", depth);
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
                    let val = self
                        .store
                        .retrieve(vindex, vpos, vsize)
                        .expect("Missing leaf value");

                    if nkey == key {
                        proof.proof_type = ProofType::Exists;
                        proof.value = Some(val);
                    } else {
                        proof.proof_type = ProofType::Collision;
                        proof.key = Some(key);
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

        // TODO: Pass the new root to commit for meta writing and stuff...
        self.store.commit();

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

                let (newindex, newpos) = tempnode.index_and_position();

                // Now it *should* be stored
                assert!(!tempnode.should_save(), "Didn't persist the node");

                // Return brand spanking new HashNode
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
                let (newindex, newpos) = node.index_and_position();
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

        assert!(t.get_root() != Digest::default());

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
