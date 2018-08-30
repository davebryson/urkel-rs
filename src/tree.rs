use hashutils::{sha3, sha3_internal, sha3_leaf, Digest};

#[derive(Clone)]
struct NodeStore {
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
struct ValueStore {
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
        data: Digest,
        index: usize,
        flags: usize,
    },
    Leaf {
        key: Digest,
        value: Vec<u8>,
        index: usize,
        flags: usize,
        data: Digest,
        vindex: usize,
        vpos: usize,
        vsize: usize,
    },
    Internal {
        left: Box<Tree>,
        right: Box<Tree>,
        index: usize,
        flags: usize,
        data: Digest,
    },
}

impl Tree {
    fn hash(&self) -> Digest {
        match self {
            Tree::Empty {} => sha3(&[0; 32]),
            Tree::Hash { data, .. } => Digest(data.0),
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
            data: Default::default(),
            index: 0,
            flags: 0,
            vindex: 0,
            vpos: 0,
            vsize: 0,
        }
    }
}

fn has_bit(key: &Digest, index: usize) -> bool {
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
    pub fn new() -> Self {
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
            .map(|t| MerkleTree::insert_leaf(t, self.keysize, nkey, value));
        self.root = newroot;
    }

    fn insert_leaf(root: Tree, keysize: usize, nkey: Digest, value: Vec<u8>) -> Tree {
        let mut depth = 0;
        let leaf_hash = sha3_leaf(nkey.clone(), &value);

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
                        key, value, data, ..
                    } => {
                        if nkey == key {
                            if leaf_hash == data {
                                // TODO: Need to clone/copy
                                return Tree::leaf(key, value);
                            }
                            break 'outer;
                        }

                        while has_bit(&nkey, depth) == has_bit(&key, depth) {
                            to_hash.push(Tree::Empty {});
                            depth += 1;
                        }

                        //TODO: I need to clone the leaf
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

        let mut new_root = Tree::leaf(nkey, value);

        // Note: into_iter allows you to move n...
        for n in to_hash.into_iter().rev() {
            depth -= 1;
            if has_bit(&nkey, depth) {
                new_root = Tree::Internal {
                    left: Box::new(n),
                    right: Box::new(new_root),
                    index: 0,
                    flags: 0,
                    data: Default::default(),
                };
            } else {
                new_root = Tree::Internal {
                    left: Box::new(new_root),
                    right: Box::new(n),
                    index: 0,
                    flags: 0,
                    data: Default::default(),
                };
            }
        }

        return new_root;
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
}
