use super::hashutils::Digest;
use nodes::Node;
use std::collections::HashMap;

pub struct MemoryDb {
    db: HashMap<[u8; 32], Node>,
}

impl Default for MemoryDb {
    fn default() -> Self {
        let map: HashMap<[u8; 32], Node> = HashMap::new();
        MemoryDb { db: map }
    }
}

impl MemoryDb {
    pub fn new() -> MemoryDb {
        let map: HashMap<[u8; 32], Node> = HashMap::new();
        MemoryDb { db: map }
    }

    // Internal should store:  <left, right>
    // Leaf should store: <key,value>
    // Bot are keyed on the the hash of the node
    pub fn put(&mut self, node: Node) -> Node {
        let k = node.hash();
        let hn = node.to_hash_node();
        self.db.insert(k.0, node);
        hn
    }

    pub fn get(&self, k: Digest) -> Option<&Node> {
        self.db.get(&k.0)
    }
}
