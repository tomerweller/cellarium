//! Mock price oracle for the repo rollup (PLAN.md §1.6). Stores one price —
//! the tUST/XLM quote as XLM-per-whole-tUST in 1e7 fixed point (PLAN.md
//! §6.1.1) — settable only by the admin key, readable by anyone. The shape
//! loosely mimics Reflector's `lastprice() -> PriceData` but this is a dev
//! mock; no real Reflector integration in this prototype.
#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env};

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OracleError {
    InvalidPrice = 1,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Price,
}

/// Price record: `price` is XLM per 1 whole tUST × 1e7; `timestamp` is the
/// ledger time of the last `set_price` (consumers reject stale reads).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

#[contract]
pub struct OracleContract;

#[contractimpl]
impl OracleContract {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Set the price; timestamp is taken from the ledger, not the caller.
    pub fn set_price(env: Env, price: i128) -> Result<(), OracleError> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if price <= 0 {
            return Err(OracleError::InvalidPrice);
        }
        let data = PriceData {
            price,
            timestamp: env.ledger().timestamp(),
        };
        env.storage().instance().set(&DataKey::Price, &data);
        Ok(())
    }

    /// Latest price, or None if never set.
    pub fn lastprice(env: Env) -> Option<PriceData> {
        env.storage().instance().get(&DataKey::Price)
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{Address, Env};

    fn setup() -> (Env, OracleContractClient<'static>, Address) {
        let env = Env::default();
        let admin = Address::generate(&env);
        let id = env.register(OracleContract, (&admin,));
        (env.clone(), OracleContractClient::new(&env, &id), admin)
    }

    #[test]
    fn set_and_read_price() {
        let (env, client, _admin) = setup();
        env.mock_all_auths();

        assert_eq!(client.lastprice(), None);

        env.ledger().with_mut(|l| l.timestamp = 1_000);
        client.set_price(&12_345_678i128);
        assert_eq!(
            client.lastprice(),
            Some(PriceData {
                price: 12_345_678,
                timestamp: 1_000
            })
        );

        // Update overwrites price and timestamp.
        env.ledger().with_mut(|l| l.timestamp = 2_000);
        client.set_price(&9_999_999i128);
        assert_eq!(
            client.lastprice(),
            Some(PriceData {
                price: 9_999_999,
                timestamp: 2_000
            })
        );
    }

    #[test]
    fn rejects_non_positive_price() {
        let (env, client, _admin) = setup();
        env.mock_all_auths();
        assert_eq!(
            client.try_set_price(&0i128),
            Err(Ok(OracleError::InvalidPrice))
        );
        assert_eq!(
            client.try_set_price(&-5i128),
            Err(Ok(OracleError::InvalidPrice))
        );
    }

    #[test]
    #[should_panic]
    fn set_price_requires_admin_auth() {
        let (_env, client, _admin) = setup();
        // No mock_all_auths: require_auth must trap.
        client.set_price(&1i128);
    }
}
