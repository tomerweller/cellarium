use soroban_sdk::{contractevent, Address, BytesN};

#[contractevent(topics = ["deposit"], data_format = "map")]
pub struct Deposit<'a> {
    #[topic]
    pub seq: &'a u64,
    pub asset: &'a u32,
    pub pk_x: &'a BytesN<32>,
    pub amount: &'a i128,
}

/// A queue-head entry refunded after the timeout (issue #1 M5): the FIFO
/// prefix is mandatory, so an unconsumable head would otherwise block every
/// deposit behind it forever with no way to recover the L1 funds.
#[contractevent(topics = ["refund"], data_format = "map")]
pub struct Refund<'a> {
    #[topic]
    pub seq: &'a u64,
    pub asset: &'a u32,
    pub to: &'a Address,
    pub amount: &'a i128,
}

#[contractevent(topics = ["batch"], data_format = "map")]
pub struct Batch<'a> {
    #[topic]
    pub batch_num: &'a u64,
    pub new_root: &'a BytesN<32>,
    /// DA commitment (5th public input) so external verifiers can audit
    /// blob availability without fetching the envelope.
    pub da_commitment: &'a BytesN<32>,
}
