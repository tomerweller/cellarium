// Account leaf encoding shared with harness tree.rs and the contract.
// Multi-asset (PLAN.md 1.1): each account holds a cash balance (asset 0,
// XLM stroops) and a collateral balance (asset 1, tUST base units).
//   bal_hash = Poseidon2([cash, coll], 2)
//   leaf     = Poseidon2([DOMAIN_LEAF, pk_x, bal_hash, nonce], 4)
// leaf = 0 when the slot is empty; pk_x == 0 is treated as the empty slot.
use dep::poseidon::poseidon2::Poseidon2;

pub global DOMAIN_LEAF: Field = 1;

// Asset ids (PLAN.md 1.2): 0 = cash (XLM), 1 = collateral (tUST).
pub global ASSET_CASH: Field = 0;
pub global ASSET_COLL: Field = 1;

pub struct Account {
    pub pk_x: Field,
    pub cash: Field,
    pub coll: Field,
    pub nonce: Field,
}

pub fn bal_hash(cash: Field, coll: Field) -> Field {
    Poseidon2::hash([cash, coll], 2)
}

pub fn leaf_value(a: Account) -> Field {
    if a.pk_x == 0 {
        0
    } else {
        Poseidon2::hash([DOMAIN_LEAF, a.pk_x, bal_hash(a.cash, a.coll), a.nonce], 4)
    }
}
