//! Mock tokenized-Treasury collateral token (tUST) for the repo rollup:
//! a minimal SEP-41 token (soroban_sdk::token::TokenInterface), 7 decimals,
//! mintable by an admin key (PLAN.md §Scope). Pure Soroban token — no classic
//! trustlines needed, so any G/C address can receive it, which keeps the e2e
//! scripts and the browser wallet demo friction-free.
//!
//! Supply invariant (PLAN.md §1.1): the rollup's balance-overflow safety
//! argument requires total supply ≤ u64::MAX base units. Enforced here by
//! `SUPPLY_CAP` on mint rather than documented-only.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token::TokenInterface,
    Address, Env, MuxedAddress, String,
};

/// Total-supply hard cap (base units). The rollup circuit range-checks L2
/// balances to u64; value conservation then bounds every balance by escrow
/// ≤ supply ≤ this cap.
pub const SUPPLY_CAP: i128 = u64::MAX as i128;

pub const DECIMALS: u32 = 7;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TokenError {
    InsufficientBalance = 1,
    InsufficientAllowance = 2,
    InvalidAmount = 3,
    SupplyCapExceeded = 4,
    AllowanceExpired = 5,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    TotalSupply,
    Balance(Address),
    Allowance(Address, Address),
}

#[contracttype]
#[derive(Clone)]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contractevent(topics = ["mint"], data_format = "single-value")]
pub struct MintEvent {
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent(topics = ["transfer"], data_format = "single-value")]
pub struct TransferEvent {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent(topics = ["burn"], data_format = "single-value")]
pub struct BurnEvent {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

fn read_balance(env: &Env, addr: &Address) -> i128 {
    env.storage().persistent().get(&DataKey::Balance(addr.clone())).unwrap_or(0)
}

fn write_balance(env: &Env, addr: &Address, amount: i128) {
    env.storage().persistent().set(&DataKey::Balance(addr.clone()), &amount);
}

fn spend_balance(env: &Env, addr: &Address, amount: i128) -> Result<(), TokenError> {
    let balance = read_balance(env, addr);
    if balance < amount {
        return Err(TokenError::InsufficientBalance);
    }
    write_balance(env, addr, balance - amount);
    Ok(())
}

fn receive_balance(env: &Env, addr: &Address, amount: i128) {
    // Cannot overflow: total supply is capped below i128::MAX.
    write_balance(env, addr, read_balance(env, addr) + amount);
}

fn check_positive(amount: i128) -> Result<(), TokenError> {
    if amount < 0 {
        return Err(TokenError::InvalidAmount);
    }
    Ok(())
}

fn spend_allowance(
    env: &Env,
    from: &Address,
    spender: &Address,
    amount: i128,
) -> Result<(), TokenError> {
    let key = DataKey::Allowance(from.clone(), spender.clone());
    let allowance: AllowanceValue = env
        .storage()
        .temporary()
        .get(&key)
        .ok_or(TokenError::InsufficientAllowance)?;
    if allowance.expiration_ledger < env.ledger().sequence() {
        return Err(TokenError::AllowanceExpired);
    }
    if allowance.amount < amount {
        return Err(TokenError::InsufficientAllowance);
    }
    env.storage().temporary().set(
        &key,
        &AllowanceValue { amount: allowance.amount - amount, ..allowance },
    );
    Ok(())
}

#[contract]
pub struct TustToken;

#[contractimpl]
impl TustToken {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Admin-only mint, capped so total supply never exceeds u64::MAX base
    /// units (the rollup's balance-overflow invariant).
    pub fn mint(env: Env, to: Address, amount: i128) -> Result<(), TokenError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        check_positive(amount)?;
        let supply: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        let new_supply = supply + amount;
        if new_supply > SUPPLY_CAP {
            return Err(TokenError::SupplyCapExceeded);
        }
        env.storage().instance().set(&DataKey::TotalSupply, &new_supply);
        receive_balance(&env, &to, amount);
        MintEvent { to, amount }.publish(&env);
        Ok(())
    }

    pub fn total_supply(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}

#[contractimpl]
impl TokenInterface for TustToken {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        let allowance: Option<AllowanceValue> =
            env.storage().temporary().get(&DataKey::Allowance(from, spender));
        match allowance {
            Some(a) if a.expiration_ledger >= env.ledger().sequence() => a.amount,
            _ => 0,
        }
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();
        check_positive(amount).unwrap();
        let key = DataKey::Allowance(from, spender);
        if amount > 0 {
            assert!(
                expiration_ledger >= env.ledger().sequence(),
                "expiration_ledger in the past"
            );
            env.storage()
                .temporary()
                .set(&key, &AllowanceValue { amount, expiration_ledger });
        } else {
            env.storage().temporary().remove(&key);
        }
    }

    fn balance(env: Env, id: Address) -> i128 {
        read_balance(&env, &id)
    }

    fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
        from.require_auth();
        check_positive(amount).unwrap();
        let to = to.address();
        spend_balance(&env, &from, amount).unwrap();
        receive_balance(&env, &to, amount);
        TransferEvent { from, to, amount }.publish(&env);
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        check_positive(amount).unwrap();
        spend_allowance(&env, &from, &spender, amount).unwrap();
        spend_balance(&env, &from, amount).unwrap();
        receive_balance(&env, &to, amount);
        TransferEvent { from, to, amount }.publish(&env);
    }

    fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        check_positive(amount).unwrap();
        spend_balance(&env, &from, amount).unwrap();
        let supply: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(supply - amount));
        BurnEvent { from, amount }.publish(&env);
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        check_positive(amount).unwrap();
        spend_allowance(&env, &from, &spender, amount).unwrap();
        spend_balance(&env, &from, amount).unwrap();
        let supply: i128 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(supply - amount));
        BurnEvent { from, amount }.publish(&env);
    }

    fn decimals(_env: Env) -> u32 {
        DECIMALS
    }

    fn name(env: Env) -> String {
        String::from_str(&env, "Mock Tokenized Treasury")
    }

    fn symbol(env: Env) -> String {
        String::from_str(&env, "tUST")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::token::TokenClient;

    fn setup() -> (Env, Address, TustTokenClient<'static>, TokenClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(TustToken, (&admin,));
        (env.clone(), admin, TustTokenClient::new(&env, &id), TokenClient::new(&env, &id))
    }

    #[test]
    fn mint_transfer_burn_roundtrip() {
        let (env, _admin, tust, token) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        tust.mint(&alice, &1_000_0000000i128);
        assert_eq!(token.balance(&alice), 1_000_0000000);
        assert_eq!(tust.total_supply(), 1_000_0000000);

        token.transfer(&alice, &bob, &400_0000000i128);
        assert_eq!(token.balance(&alice), 600_0000000);
        assert_eq!(token.balance(&bob), 400_0000000);

        token.burn(&bob, &100_0000000i128);
        assert_eq!(token.balance(&bob), 300_0000000);
        assert_eq!(tust.total_supply(), 900_0000000);

        assert_eq!(token.decimals(), 7);
    }

    #[test]
    fn supply_cap_enforced() {
        let (env, _admin, tust, _token) = setup();
        let alice = Address::generate(&env);
        tust.mint(&alice, &(SUPPLY_CAP - 10));
        assert_eq!(
            tust.try_mint(&alice, &11i128),
            Err(Ok(TokenError::SupplyCapExceeded))
        );
        tust.mint(&alice, &10i128); // exactly at cap is fine
        assert_eq!(tust.total_supply(), SUPPLY_CAP);
    }

    #[test]
    fn transfer_from_respects_allowance() {
        let (env, _admin, tust, token) = setup();
        let alice = Address::generate(&env);
        let spender = Address::generate(&env);
        let bob = Address::generate(&env);

        tust.mint(&alice, &100i128);
        token.approve(&alice, &spender, &60i128, &1000u32);
        assert_eq!(token.allowance(&alice, &spender), 60);

        token.transfer_from(&spender, &alice, &bob, &50i128);
        assert_eq!(token.balance(&bob), 50);
        assert_eq!(token.allowance(&alice, &spender), 10);

        // Exceeding the remaining allowance traps.
        assert!(token.try_transfer_from(&spender, &alice, &bob, &11i128).is_err());
    }

    #[test]
    fn insufficient_balance_rejected() {
        let (env, _admin, tust, token) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        tust.mint(&alice, &10i128);
        assert!(token.try_transfer(&alice, &bob, &11i128).is_err());
    }
}
