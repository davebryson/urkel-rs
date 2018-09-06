extern crate tiny_keccak;

pub mod hashutils;
pub mod proof;
pub mod tree;

use tiny_keccak::Keccak;

trait Hello {
    fn hey(&self) -> &'static str;
}

struct Ex;

impl Hello for Ex {
    fn hey(&self) -> &'static str {
        "Hey there"
    }
}

fn try_it(h: &Hello) -> String {
    String::from(format!("You said {}", h.hey()))
}

struct Example<'a> {
    hfn: &'a Hello,
}

impl<'a> Example<'a> {
    fn run(&self) -> &'static str {
        self.hfn.hey()
    }
}

type Digest = [u8; 32];

const LEAF_PREFIX: &[u8] = &[0x00u8];

fn hash_many(args: &[&[u8]]) -> Digest {
    let mut hash = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];
    for a in args {
        hash.update(a);
    }
    hash.finalize(&mut res);
    res
}

#[cfg(test)]
mod tests {
    use hash_many;
    use hashutils::sha3;
    use proof::ProofType;
    use tree::MerkleTree;
    use try_it;
    use Ex;
    use Example;
    use LEAF_PREFIX;

    #[test]
    fn should_insert_and_get() {
        let mut t = MerkleTree::new();
        let key1 = sha3(b"name-1");
        let key2 = sha3(b"name-2");
        t.insert(key1, Vec::from("value-1"));
        t.insert(key2, Vec::from("value-2"));
        let rootHash = t.get_root();

        //assert_eq!(
        //    "0xe027af0341702c08c4cba55912b0d57be8169a3cf78b3a46d71b0fba8493af57",
        //    format!("{:x}", rootHash)
        //);

        assert_eq!(t.get(key1), Some(Vec::from("value-1")));
        assert_eq!(t.get(key2), Some(Vec::from("value-2")));

        let prf = t.prove(key2);
        let pv = prf.clone();

        assert!(prf.is_some());

        let pt = prf.unwrap();
        let result = match pt.proof_type {
            ProofType::Exists => true,
            _ => false,
        };
        assert!(result);

        let noproof = t.prove(sha3(b"Doesn't exist"));
        assert!(noproof.is_some());

        let works = match noproof {
            Some(v) => {
                if v.proof_type == ProofType::Collision {
                    true
                } else {
                    false
                }
            }
            _ => false,
        };

        assert!(works);
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

        let result = match prf {
            Some(mut pv) => match pv.verify(t.get_root(), key2, 256) {
                Ok(_) => true,
                Err(m) => {
                    println!("Reason {}", m);
                    false
                }
            },
            _ => false,
        };

        assert!(result);
    }

    #[test]
    fn test_trait() {
        let r = try_it(&Ex {});
        assert_eq!("You said Hey there", r);

        let e1 = Example { hfn: &Ex {} };
        assert_eq!("Hey there", e1.run());
    }

    #[test]
    fn with_hash() {
        let r = hash_many(&[LEAF_PREFIX, &[1, 2, 3], &[4, 5, 6]]);
        let r1 = hash_many(&[LEAF_PREFIX, &[1, 2, 3], &[4, 5, 6]]);
        println!("{:?}", r);
        assert!(r == r1);
    }

}
