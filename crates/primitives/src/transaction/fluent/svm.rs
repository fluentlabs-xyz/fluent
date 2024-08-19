use crate::{TxType, U256};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, ChainId, TxKind, B256};
use proptest::prelude::BoxedStrategy;
use reth_codecs::Compact;

#[derive(
    Debug, Default, Clone, PartialEq, Eq, Hash, Compact, serde::Serialize, serde::Deserialize,
)]
pub struct SolanaEnvironment {
    /// Added as EIP-pub 155: Simple replay attack protection
    pub chain_id: Option<ChainId>,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_price: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    pub max_fee_per_gas: u128,
    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    pub max_priority_fee_per_gas: Option<u128>,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,

    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl SolanaEnvironment {
    pub fn new() -> Self {
        Self {
            chain_id: None,
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: None,
            to: TxKind::Call(Address::ZERO),
            value: U256::from(0),
            input: Bytes::new(),
        }
    }
    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
    pub const fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    pub const fn kind(&self) -> TxKind {
        self.to
    }
    pub const fn tx_type(&self) -> TxType {
        TxType::FluentV1
    }
    pub const fn value(&self) -> &U256 {
        &self.value
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    pub const fn access_list(&self) -> Option<&AccessList> {
        None
    }
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub const fn is_dynamic_fee(&self) -> bool {
        false
    }
    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }
    pub const fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.max_priority_fee_per_gas
    }

    pub const fn priority_fee_or_price(&self) -> u128 {
        if let Some(max_priority_fee_per_gas) = self.max_priority_fee_per_gas {
            max_priority_fee_per_gas
        } else {
            self.gas_price
        }
    }
    pub const fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match base_fee {
            None => self.max_fee_per_gas,
            Some(base_fee) => {
                // if the tip is greater than the max priority fee per gas, set it to the max
                // priority fee per gas + base fee
                let tip = self.max_fee_per_gas.saturating_sub(base_fee as u128);

                let max_priority_fee_per_gas =
                    if let Some(max_priority_fee_per_gas) = self.max_priority_fee_per_gas {
                        max_priority_fee_per_gas
                    } else {
                        self.gas_price
                    };
                if tip > max_priority_fee_per_gas {
                    max_priority_fee_per_gas + base_fee as u128
                } else {
                    // otherwise return the max fee per gas
                    self.max_fee_per_gas
                }
            }
        }
    }
    pub const fn input(&self) -> &Bytes {
        &self.input
    }
    pub const fn tx_kind(&self) -> TxKind {
        self.to
    }
    pub fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        None
    }
    pub fn set_value(&mut self, value: U256) {
        self.value = value;
    }
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.gas_limit = gas_limit;
    }
    pub fn set_input(&mut self, input: Bytes) {
        self.input = input;
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for SolanaEnvironment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Implement arbitrary generation for SolanaEnvironment
        todo!("Implement arbitrary for SolanaEnvironment")
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::arbitrary::Arbitrary for SolanaEnvironment {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Implement arbitrary strategy for SolanaEnvironment
        // TODO: fluent_tx_d1r1 add implementation
        todo!("Implement arbitrary strategy for SolanaEnvironment")
    }

    fn arbitrary() -> Self::Strategy {
        Self::arbitrary_with(())
    }
}
