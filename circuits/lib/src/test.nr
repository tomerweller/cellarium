// M2 checkpoint: byte-for-byte agreement with the Rust harness
// (`cargo run -p harness -- vectors` regenerates these constants; the same
// values are pinned in harness/src/tree.rs tests via the shared code path).
use crate::account::{bal_hash, leaf_value, Account};
use crate::merkle::{compute_root, hash2, update_root, DEPTH};
use crate::tx::{DOMAIN_DEP2, DOMAIN_WD2};
use dep::poseidon::poseidon2::Poseidon2;

global HASH2_1_2: Field = 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383;
global HASH4_1_2_3_4: Field = 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9;
global EMPTY_ROOT_D8: Field = 0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1;
global BAL_HASH_100_40: Field = 0x20e1be360698358680d08b979866b37bac666f5d35577df26f51e24487839c65;
global LEAF_1234_100_40_0: Field = 0x2cadc331fd61be1dc52aa0bf0d748b484e0ad61410836487abc8cc50691db5fd;
global ROOT_LEAF_AT_5: Field = 0x2c3f024049095d0b2854eb0e4dc51807bbb8faa3dd3daafbe9ad81bfaa010c8d;
global DA_FOLD_0_42: Field = 0x04753fb4f4ed6d02388a18f3b84e56dfc5b22dcd77ec8acf81ca9257bdfae3e3;
global DEP2_FOLD_0_1234_COLL_77: Field = 0x0df829c73338b1e69592367d91fdb919da8f5cb28dcf0be7c762563b2a53a21f;
global WD2_FOLD_0_1234_COLL_77: Field = 0x05ea7897c2db479adeb2548f134c58c9ad6b8676a1b7469faa6e9a8843ac6a11;

fn zeros() -> [Field; DEPTH + 1] {
    let mut z = [0; DEPTH + 1];
    for i in 0..DEPTH {
        z[i + 1] = hash2(z[i], z[i]);
    }
    z
}

#[test]
fn hash2_matches_harness() {
    assert(hash2(1, 2) == HASH2_1_2);
}

#[test]
fn hash4_matches_harness() {
    assert(Poseidon2::hash([1, 2, 3, 4], 4) == HASH4_1_2_3_4);
}

#[test]
fn empty_root_matches_harness() {
    let z = zeros();
    assert(z[DEPTH] == EMPTY_ROOT_D8);
}

#[test]
fn bal_hash_matches_harness() {
    assert(bal_hash(100, 40) == BAL_HASH_100_40);
}

#[test]
fn leaf_hash_matches_harness() {
    let leaf = leaf_value(Account { pk_x: 1234, cash: 100, coll: 40, nonce: 0 });
    assert(leaf == LEAF_1234_100_40_0);
}

#[test]
fn da_fold_matches_harness() {
    // The validium DA commitment fold: acc' = P2([DOMAIN_DA, acc, msg], 3).
    assert(Poseidon2::hash([crate::tx::DOMAIN_DA, 0, 42], 3) == DA_FOLD_0_42);
}

#[test]
fn dep2_fold_matches_harness() {
    // acc' = P2([DOMAIN_DEP2, acc, P2([pk_x, asset, amount], 3)], 3).
    let entry = Poseidon2::hash([1234, 1, 77], 3);
    assert(Poseidon2::hash([DOMAIN_DEP2, 0, entry], 3) == DEP2_FOLD_0_1234_COLL_77);
}

#[test]
fn wd2_fold_matches_harness() {
    // acc' = P2([DOMAIN_WD2, acc, P2([dest, asset, amount], 3)], 3).
    let entry = Poseidon2::hash([1234, 1, 77], 3);
    assert(Poseidon2::hash([DOMAIN_WD2, 0, entry], 3) == WD2_FOLD_0_1234_COLL_77);
}

#[test]
fn empty_account_is_zero_leaf() {
    assert(leaf_value(Account { pk_x: 0, cash: 0, coll: 0, nonce: 0 }) == 0);
}

fn zero_siblings() -> [Field; DEPTH] {
    let z = zeros();
    let mut siblings = [0; DEPTH];
    for i in 0..DEPTH {
        siblings[i] = z[i];
    }
    siblings
}

#[test]
fn single_leaf_root_matches_harness() {
    // Insert leaf(1234, 100, 40, 0) at index 5 of the empty depth-8 tree;
    // siblings are the zero ladder of an otherwise-empty tree.
    let leaf = leaf_value(Account { pk_x: 1234, cash: 100, coll: 40, nonce: 0 });
    assert(compute_root(leaf, 5, zero_siblings()) == ROOT_LEAF_AT_5);
}

#[test]
fn update_root_roundtrip() {
    let leaf = leaf_value(Account { pk_x: 1234, cash: 100, coll: 40, nonce: 0 });
    // empty -> leaf at index 5 must land on the harness root.
    let new_root = update_root(0, leaf, 5, zero_siblings(), EMPTY_ROOT_D8);
    assert(new_root == ROOT_LEAF_AT_5);
}

#[test(should_fail)]
fn update_root_rejects_wrong_old_root() {
    let _ = update_root(0, 1, 5, zero_siblings(), ROOT_LEAF_AT_5);
}
