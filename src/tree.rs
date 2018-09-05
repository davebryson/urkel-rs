use hashutils::{sha3, sha3_internal, sha3_leaf, Digest};
use proof::{Proof, ProofType};

#[derive(Clone)]
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

#[derive(Clone)]
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
    fn hash(&self) -> Digest {
        match self {
            Tree::Empty {} => sha3(&[0; 32]),
            Tree::Hash { params } => Digest(params.data.0),
            Tree::Leaf { key, value, .. } => sha3_leaf(Digest(key.0), value),
            Tree::Internal { left, right, .. } => {
                let lh = left.as_ref().hash();
                let rh = right.as_ref().hash();
                sha3_internal(lh, rh)
            }
        }
    }

    fn empty() -> Self {
        Tree::Empty {}
    }

    fn leaf(key: Digest, value: Vec<u8>) -> Self {
        Tree::Leaf {
            key: key,
            value: value,
            params: Default::default(),
            content: Default::default(),
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
}

impl MerkleTree {
    pub fn new() -> MerkleTree {
        MerkleTree {
            root: Some(Tree::empty()),
            keysize: 256,
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

        let mut new_root = Tree::leaf(nkey, value);
        let leaf_hash = new_root.hash();

        let mut to_hash = Vec::<Tree>::new();
        loop {
            match root {
                Tree::Empty {} => break,
                Tree::Hash { .. } => { /*should push current*/ }
                Tree::Leaf {
                    key, value, params, ..
                } => {
                    if nkey == key {
                        if leaf_hash == params.data {
                            // TODO: Need to clone/copy?
                            return Tree::leaf(key, value);
                        }
                        break;
                    }

                    while has_bit(&nkey, depth) == has_bit(&key, depth) {
                        to_hash.push(Tree::Empty {});
                        depth += 1;
                    }

                    //TODO: I need to clone the leaf?
                    to_hash.push(Tree::leaf(key, value));

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
                }
            }
        }

        // Note: into_iter allows you to move n...
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

        return new_root;
    }

    /*
    fn insert_leaf(root: Tree, keysize: usize, nkey: Digest, value: Vec<u8>) -> Tree {
        let mut depth = 0;
        let mut new_root = Tree::leaf(nkey, value);
        let leaf_hash = new_root.hash();

        let mut to_hash = Vec::<Tree>::new();
        let mut current = Vec::<Tree>::new();
        current.push(root);

        'outer: loop {
            let mut next = Vec::<Tree>::new();
            while !current.is_empty() {
                let n = current.remove(0);
                match n {
                    Tree::Empty {} => break 'outer,
                    Tree::Hash { .. } => { /*should push current*/ }
                    Tree::Leaf {
                        key, value, params, ..
                    } => {
                        if nkey == key {
                            if leaf_hash == params.data {
                                // TODO: Need to clone/copy?
                                return Tree::leaf(key, value);
                            }
                            break 'outer;
                        }

                        while has_bit(&nkey, depth) == has_bit(&key, depth) {
                            to_hash.push(Tree::Empty {});
                            depth += 1;
                        }

                        //TODO: I need to clone the leaf?
                        to_hash.push(Tree::leaf(key, value));

                        depth += 1;
                        break 'outer;
                    }
                    Tree::Internal { left, right, .. } => {
                        if depth == keysize {
                            panic!(format!("Missing node at depth {}", depth));
                        }

                        if has_bit(&nkey, depth) {
                            to_hash.push(*left);
                            next.push(*right);
                        } else {
                            to_hash.push(*right);
                            next.push(*left);
                        }
                        break;
                    }
                }
            }
            current = next;
        }

        // Note: into_iter allows you to move n...
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

        return new_root;
    }*/

    pub fn get(&self, nkey: Digest) -> Option<Vec<u8>> {
        let mut depth = 0;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Tree::Leaf { key, value, .. } => {
                    if nkey != *key {
                        return None;
                    }
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
                _ => return None,
            }
        }
    }

    /*pub fn prove(&mut self, key: Digest) -> Option<Proof> {
        //let current_root = self.root.as_mut();
        let result = self
            .root
            .map(|ref mut t| MerkleTree::do_proof(t, key, self.keysize));
        //let result = self
        //    .root
        //    .take()
        //    .map(|t| MerkleTree::do_proof(t, key, self.keysize));
        result
    }*/

    pub fn prove(&self, nkey: Digest) -> Option<Proof> {
        let mut depth = 0;
        let mut proof = Proof::new();

        let keysize = self.keysize;
        let mut current = self.root.as_ref().unwrap();
        loop {
            match current {
                Tree::Empty {} => break,
                Tree::Hash { .. } => { /*should push current*/ }
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

        return Some(proof);
    }
}
