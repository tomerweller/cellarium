use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env};

/// Asset ids (DESIGN.md): 0 = cash (XLM), 1 = collateral (tUST).
pub const ASSET_CASH: u32 = 0;
pub const ASSET_COLL: u32 = 1;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Custody token contract per asset id.
    Token(u32),
    /// Mock price oracle contract (PLAN.md 1.6).
    Oracle,
    Vk,
    Root,
    BatchNum,
    /// FIFO deposit queue head/tail per asset id.
    DepHead(u32),
    DepTail(u32),
    /// FIFO deposit queue entry (ring buffer by sequence number) per asset.
    Dep(u32, u64),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDeposit {
    pub pk_x: BytesN<32>,
    pub amount: i128,
}

pub fn set_token(env: &Env, asset: u32, token: &Address) {
    env.storage().instance().set(&DataKey::Token(asset), token);
}

pub fn get_token(env: &Env, asset: u32) -> Address {
    env.storage().instance().get(&DataKey::Token(asset)).unwrap()
}

pub fn set_oracle(env: &Env, oracle: &Address) {
    env.storage().instance().set(&DataKey::Oracle, oracle);
}

pub fn get_oracle(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Oracle).unwrap()
}

pub fn set_vk(env: &Env, vk: &Bytes) {
    env.storage().instance().set(&DataKey::Vk, vk);
}

pub fn get_vk(env: &Env) -> Bytes {
    env.storage().instance().get(&DataKey::Vk).unwrap()
}

pub fn set_root(env: &Env, root: &BytesN<32>) {
    env.storage().instance().set(&DataKey::Root, root);
}

pub fn get_root(env: &Env) -> BytesN<32> {
    env.storage().instance().get(&DataKey::Root).unwrap()
}

pub fn set_batch_num(env: &Env, n: u64) {
    env.storage().instance().set(&DataKey::BatchNum, &n);
}

pub fn get_batch_num(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::BatchNum).unwrap_or(0)
}

pub fn dep_head(env: &Env, asset: u32) -> u64 {
    env.storage().instance().get(&DataKey::DepHead(asset)).unwrap_or(0)
}

pub fn dep_tail(env: &Env, asset: u32) -> u64 {
    env.storage().instance().get(&DataKey::DepTail(asset)).unwrap_or(0)
}

pub fn enqueue_deposit(env: &Env, asset: u32, dep: &PendingDeposit) -> u64 {
    let tail = dep_tail(env, asset);
    env.storage().persistent().set(&DataKey::Dep(asset, tail), dep);
    env.storage().instance().set(&DataKey::DepTail(asset), &(tail + 1));
    tail
}

pub fn get_deposit(env: &Env, asset: u32, seq: u64) -> PendingDeposit {
    env.storage().persistent().get(&DataKey::Dep(asset, seq)).unwrap()
}

pub fn dequeue_deposits(env: &Env, asset: u32, count: u64) {
    let head = dep_head(env, asset);
    for seq in head..head + count {
        env.storage().persistent().remove(&DataKey::Dep(asset, seq));
    }
    env.storage().instance().set(&DataKey::DepHead(asset), &(head + count));
}
