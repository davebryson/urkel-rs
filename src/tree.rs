use hashutils::{sha3, sha3_internal, sha3_value, sha3_zero_hash, Digest};
use memorydb::MemoryDb;
use proof::{Proof, ProofType};
use std::fmt;

/// Store the hash of the node along with file store information
#[derive(Clone, Copy)]
pub struct NodeStore {
    data: Digest,
    index: usize,
    flags: usize,
}

impl Default for NodeStore {
    fn default() -> Self {
        NodeStore {
            data: Default::default(),
            index: 0,
            flags: 0,
        }
    }
}

/// Used in leaf to store the actual value - mainly needed for filestore information
#[derive(Clone, Copy)]
pub struct ValueStore {
    vindex: usize,
    vpos: usize,
    vsize: usize,
}

impl Default for ValueStore {
    fn default() -> Self {
        ValueStore {
            vindex: 0,
            vpos: 0,
            vsize: 0,
        }
    }
}

/// Change to Node??
pub enum Tree {
    Empty {},
    Hash {
        params: NodeStore,
    },
    Leaf {
        key: Digest,
        value: Vec<u8>,
        params: NodeStore,
        content: ValueStore,
    },
    Internal {
        left: Box<Tree>,
        right: Box<Tree>,
        params: NodeStore,
    },
}

impl Tree {
    // Generate hash for specific node
    pub fn hash(&self) -> Digest {
        match self {
            Tree::Empty {} => sha3_zero_hash(),
            Tree::Hash { params } => Digest(params.data.0),
            Tree::Leaf {
                key: _,
                value: _,
                params,
                ..
            } => Digest(params.data.0),
            Tree::Internal { left, right, .. } => {
                let lh = left.as_ref().hash();
                let rh = right.as_ref().hash();
                sha3_internal(lh, rh)
            }
        }
    }

    // Convert current node into a HashNode. Can't seem to make From/Into trait work for an enum
    pub fn to_hash_node(&self) -> Self {
        match self {
            Tree::Leaf {
                key: _,
                value: _,
                params,
                ..
            } => Tree::Hash {
                params: NodeStore {
                    data: self.hash(),
                    index: params.index,
                    flags: params.flags,
                },
            },
            Tree::Internal {
                left: _,
                right: _,
                params,
            } => Tree::Hash {
                params: NodeStore {
                    data: self.hash(),
                    index: params.index,
                    flags: params.flags,
                },
            },
            Tree::Hash { params } => Tree::Hash { params: *params },
            Tree::Empty {} => Tree::empty(),
        }
    }

    // Create an Empty Node
    fn empty() -> Self {
        Tree::Empty {}
    }

    // Create basic Leaf Node
    fn leaf(key: Digest, value: Vec<u8>, params: NodeStore) -> Self {
        Tree::Leaf {
            key,
            value,
            params,
            content: Default::default(),
        }
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Tree::Empty {} => write!(f, "Tree::Empty"),
            Tree::Leaf { key, value, .. } => write!(f, "Tree:Leaf({:?})", value),
            Tree::Internal { left, right, .. } => {
                write!(f, "Tree:Internal({:?}, {:?})", left, right)
            }
            Tree::Hash { params } => write!(f, "Tree::Hash()"),
        }
    }
}

pub fn has_bit(key: &Digest, index: usize) -> bool {
    let oct = index >> 3;
    let bit = index & 7;
    match (key.0[oct] >> (7 - bit)) & 1 {
        0 => false,
        1 => true,
        _ => false,
    }
}

pub struct MerkleTree {
    root: Option<Tree>,
    keysize: usize,
    store: MemoryDb,
}

impl MerkleTree {
    pub fn new() -> MerkleTree {
        MerkleTree {
            root: Some(Tree::empty()),
            keysize: 256,
            store: Default::default(),
        }
    }

    pub fn get_root(&self) -> Digest {
        let r = self.root.as_ref().expect("Tree root was None");
        r.hash()
    }

    pub fn insert(&mut self, nkey: Digest, value: Vec<u8>) {
        let newroot = self
            .root
            .take()
            .map(|t| MerkleTree::do_insert(t, self.keysize, nkey, value));
        self.root = newroot;
    }

    fn do_insert(mut root: Tree, keysize: usize, nkey: Digest, value: Vec<u8>) -> Tree {
        let mut depth = 0;
        let leaf_hash = sha3_value(nkey, value.as_slice());
        let mut to_hash = Vec::<Tree>::new();

        loop {
            match root {
                Tree::Empty {} => break,
                Tree::Hash { .. } => { /*should pull from store*/ }
                Tree::Leaf {
                    key, value, params, ..
                } => {
                    if nkey == key {
                        if leaf_hash == params.data {
                            return Tree::leaf(key, value, params);
                        }
                        break;
                    }

                    while has_bit(&nkey, depth) == has_bit(&key, depth) {
                        to_hash.push(Tree::Empty {});
                        depth += 1;
                    }

                    to_hash.push(Tree::leaf(key, value, params));

                    depth += 1;
                    break;
                }
                Tree::Internal { left, right, .. } => {
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
        let mut new_root = Tree::leaf(nkey, value, params);

        for n in to_hash.into_iter().rev() {
            depth -= 1;
            if has_bit(&nkey, depth) {
                new_root = Tree::Internal {
                    left: Box::new(n),
                    right: Box::new(new_root),
                    params: Default::default(),
                };
            } else {
                new_root = Tree::Internal {
                    left: Box::new(new_root),
                    right: Box::new(n),
                    params: Default::default(),
                };
            }
        }

        new_root
    }

    pub fn get(&self, nkey: Digest) -> Option<Vec<u8>> {
        let mut depth = 0;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Tree::Leaf { key, value, .. } => {
                    if nkey != *key {
                        return None;
                    }
                    // if the current node has a value return it
                    // else pull from store
                    return Some(value.to_vec());
                }
                Tree::Internal { left, right, .. } => {
                    if has_bit(&nkey, depth) {
                        current = &*right;
                    } else {
                        current = &*left;
                    }
                    depth += 1;
                }
                Tree::Hash { params } => {
                    // Pull from storage
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
        let mut proof = Proof::new();

        let keysize = self.keysize;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Tree::Empty {} => break,
                Tree::Hash { .. } => { /* TODO: should pull from store */ }
                Tree::Internal { left, right, .. } => {
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
                Tree::Leaf { key, value, .. } => {
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

    // Commit subtree to storage and return a new Hashnode root.
    pub fn commit(&mut self) {
        let newroot = self.root.take().map(|t| self.write(t));
        self.root = newroot;
    }

    fn write(&mut self, n: Tree) -> Tree {
        match n {
            Tree::Empty {} => Tree::empty(),
            Tree::Internal { left, right, .. } => {
                // Don't necessarily like the recursive call
                // but not sure of a better way to do it...
                let left_result = self.write(*left);
                let right_result = self.write(*right);

                let mut node = Tree::Internal {
                    left: Box::new(left_result),
                    right: Box::new(right_result),
                    params: Default::default(),
                };

                println!("Store node {:x}", node.hash());
                self.store.put(node)
            }
            Tree::Leaf {
                key, value, params, ..
            } => {
                // Store node
                //println!("Store leaf {:x}", n.hash());
                let l = Tree::leaf(key, value.to_vec(), params);
                self.store.put(l)
            }
            Tree::Hash { params } => Tree::Hash { params: params },
        }
    }
}
