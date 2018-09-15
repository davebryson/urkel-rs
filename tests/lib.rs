extern crate urkel_rs;

use urkel_rs::hashutils::sha3;
use urkel_rs::proof::ProofType;
use urkel_rs::store::Store;
use urkel_rs::UrkelTree;

#[test]
fn should_insert_and_get() {
    let mut t = UrkelTree::default();
    let key1 = sha3(b"name-1");
    let key2 = sha3(b"name-2");

    t.insert(key1, Vec::from("value-1"));
    t.insert(key2, Vec::from("value-2"));

    assert_eq!(
        "0xe027af0341702c08c4cba55912b0d57be8169a3cf78b3a46d71b0fba8493af57",
        format!("{:x}", t.get_root())
    );

    assert_eq!(t.get(key1), Some(Vec::from("value-1")));
    assert_eq!(t.get(key2), Some(Vec::from("value-2")));

    // Test good proof
    let prf = t.prove(key2);
    assert!(prf.is_some());
    if let Some(pt) = prf {
        assert!(pt.proof_type == ProofType::Exists);
        assert!(pt.value == Some(Vec::from("value-2")));
    }

    // Test collision
    let noproof = t.prove(sha3(b"doesn't exist"));
    assert!(noproof.is_some());
    if let Some(np) = noproof {
        assert!(np.proof_type == ProofType::Collision);
        assert!(np.key.is_some());
        assert!(np.hash.is_some());
    }
}

#[test]
fn should_handle_get_on_nullnode() {
    let t = UrkelTree::default();
    assert_eq!(t.get(sha3(b"name-2")), None);
}

#[test]
fn should_verify() {
    let mut t = UrkelTree::default();
    let key1 = sha3(b"name-1");
    let key2 = sha3(b"name-2");
    t.insert(key1, Vec::from("value-1"));
    t.insert(key2, Vec::from("value-2"));

    let prf = t.prove(key2);
    assert!(prf.is_some());

    if let Some(mut p) = prf {
        let r = p.verify(t.get_root(), key2, 256);
        assert!(r.is_ok());
    }
}

#[test]
fn santity_check() {
    let v = sha3(b"Helloworld");
    assert_eq!(32, v.0.len());

    assert_eq!(
        "0xac1824d4443ee9a8fcb7026f1b4751b60e0c716ad2d7eaaf8b76b2c44707e6ae",
        format!("{:x}", v)
    );
}

#[test]
fn should_commit() {
    let mut t = UrkelTree::default();
    for i in 0..5 {
        let k = sha3(format!("name-{}", i).as_bytes());
        let v = Vec::from(format!("value-{}", i));
        t.insert(k, v);
    }

    t.commit();

    assert_eq!(t.get(sha3(b"name-1")), Some(Vec::from("value-1")));
}

fn store_test() {
    let mut store = Store::open();
    store.write(String::from("one").as_bytes());
    store.write(String::from("two").as_bytes());
    println!("Pos {}", store.position());
}
