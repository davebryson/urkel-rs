use hashutils::Digest;
use std::collections::HashMap;
use tree::Tree;

pub struct MemoryDb {
    db: HashMap<[u8; 32], Tree>,
}

impl Default for MemoryDb {
    fn default() -> Self {
        let map: HashMap<[u8; 32], Tree> = HashMap::new();
        MemoryDb { db: map }
    }
}

impl MemoryDb {
    pub fn new() -> MemoryDb {
        let map: HashMap<[u8; 32], Tree> = HashMap::new();
        MemoryDb { db: map }
    }

    pub fn put(&mut self, node: Tree) -> Tree {
        let k = node.hash();
        let hn = node.to_hash_node();
        self.db.insert(k.0, node);
        hn
    }

    pub fn get(&self, k: Digest) -> Option<&Tree> {
        self.db.get(&k.0)
    }
}
