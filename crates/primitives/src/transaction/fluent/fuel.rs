use crate::{hex, Bytes, ChainId, Signature, TxKind, TxType, B256, U256};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::Address;
use alloy_rlp::{encode, length_of_length, Decodable, Encodable, Error as RlpError, Header};
use fluentbase_core::fvm::helpers::fuel_testnet_consensus_params_from;
use fuel_core_types::fuel_types::canonical::Deserialize;
use fuel_tx::{
    field::{Inputs, Witnesses},
    Chargeable, ConsensusParameters, Transaction, UniqueIdentifier, Witness,
};
use proptest::prelude::BoxedStrategy;
use reth_codecs::Compact;
use reth_primitives_traits::constants::MIN_PROTOCOL_BASE_FEE;

pub struct FuelTransaction(Transaction);
impl FuelTransaction {
    pub fn new(transaction: Transaction) -> Self {
        Self(transaction)
    }
    pub fn original_tx(self) -> Transaction {
        self.0
    }
    pub fn inputs(&self) -> Result<&Vec<fuel_tx::Input>, RlpError> {
        match &self.0 {
            Transaction::Script(t) => Ok(t.inputs()),
            Transaction::Create(t) => Ok(t.inputs()),
            Transaction::Upload(t) => Ok(t.inputs()),
            Transaction::Upgrade(t) => Ok(t.inputs()),
            Transaction::Mint(t) => Err(alloy_rlp::Error::Custom("mint tx unsupported")),
        }
    }
    pub fn first_input(&self) -> Result<fuel_tx::Input, RlpError> {
        Ok(self.inputs()?.first().cloned().ok_or(RlpError::Custom("at least 1 input expected"))?)
    }
    pub fn gas_limit(&self, cp: &ConsensusParameters) -> Result<u64, RlpError> {
        match &self.0 {
            Transaction::Script(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            Transaction::Create(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            Transaction::Upload(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            Transaction::Upgrade(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            Transaction::Mint(_) => Err(RlpError::Custom("mint tx unsupported")),
        }
    }
    pub fn first_owner(&self) -> Result<&fuel_core_types::fuel_types::Address, RlpError> {
        let Some(input) = self.inputs()?.first() else {
            return Err(RlpError::Custom("fuel: only txs with exactly 1 input are supported"));
        };
        let Some(owner) = input.input_owner() else {
            return Err(RlpError::Custom("fuel: only txs with owner are supported"));
        };
        Ok(owner)
    }
    pub fn recover_first_owner(
        &self,
        cp: &ConsensusParameters,
    ) -> Result<fuel_core_types::fuel_types::Address, RlpError> {
        let owner = self
            .first_witness()?
            .recover_witness(&self.0.id(&cp.chain_id()), 0)
            .map_err(|v| RlpError::Custom("failed to recover first witness"))?;
        Ok(owner)
    }
    pub fn witnesses(&self) -> Result<&Vec<Witness>, RlpError> {
        match &self.0 {
            Transaction::Script(t) => Ok(t.witnesses()),
            Transaction::Create(t) => Ok(t.witnesses()),
            Transaction::Upload(t) => Ok(t.witnesses()),
            Transaction::Upgrade(t) => Ok(t.witnesses()),
            Transaction::Mint(_) => Err(RlpError::Custom("mint tx unsupported")),
        }
    }
    pub fn first_witness(&self) -> Result<&Witness, RlpError> {
        match &self.0 {
            Transaction::Script(t) => Ok(t
                .witnesses()
                .first()
                .ok_or(RlpError::Custom("at least 1 witness must be presented"))?),
            Transaction::Create(t) => Ok(t
                .witnesses()
                .first()
                .ok_or(RlpError::Custom("at least 1 witness must be presented"))?),
            Transaction::Upload(t) => Ok(t
                .witnesses()
                .first()
                .ok_or(RlpError::Custom("at least 1 witness must be presented"))?),
            Transaction::Upgrade(t) => Ok(t
                .witnesses()
                .first()
                .ok_or(RlpError::Custom("at least 1 witness must be presented"))?),
            Transaction::Mint(_) => Err(RlpError::Custom("mint tx unsupported")),
        }
    }
}

#[derive(
    Debug, Default, Clone, PartialEq, Eq, Hash, Compact, serde::Serialize, serde::Deserialize,
)]
pub struct FuelEnvironment {
    original_tx_bytes: Bytes,
    chain_id: Option<ChainId>,
    access_list: Option<AccessList>,
    gas_limit: u64,
    tx_kind: TxKind,
    owner: B256,
    input: Bytes,
}

impl FuelEnvironment {
    pub fn new(data: Bytes) -> Result<Self, RlpError> {
        let tx: Transaction = Self::fuel_tx_from_bytes(&data)?;
        let fuel_tx = FuelTransaction(tx);
        let consensus_params = Self::generate_consensus_params(fluentbase_core::DEVNET_CHAIN_ID);
        let mut alt = Vec::<AccessListItem>::new();
        let owner = fuel_tx.first_owner()?;
        let recovered_first_owner = fuel_tx.recover_first_owner(&consensus_params)?;
        if owner != &recovered_first_owner {
            return Err(RlpError::Custom("provided owner doesn't match recovered"))
        }
        alt.push(AccessListItem {
            address: Address::from_slice(&owner[12..]),
            storage_keys: Default::default(),
        });
        let instance = Self {
            original_tx_bytes: data,
            chain_id: Some(ChainId::from(consensus_params.chain_id())),
            access_list: Some(AccessList(alt)),
            gas_limit: fuel_tx
                .gas_limit(&consensus_params)
                .map_err(|e| RlpError::Custom("failed to get gas limit from tx"))?,
            // TODO setup custom kind?
            tx_kind: TxKind::Create,
            owner: owner.0.into(),
            ..Default::default()
        };

        Ok(instance)
    }
    pub fn fuel_tx_from_bytes(data: &Bytes) -> Result<Transaction, RlpError> {
        Transaction::from_bytes(data.as_ref())
            .map_err(|e| RlpError::Custom(&"failed to parse fuel tx"))
    }
    pub fn generate_consensus_params(chain_id: u64) -> ConsensusParameters {
        fuel_testnet_consensus_params_from(
            None,
            None,
            None,
            fuel_core_types::fuel_types::ChainId::new(chain_id),
            None,
        )
    }
    pub fn consensus_params(&self) -> ConsensusParameters {
        fuel_testnet_consensus_params_from(
            None,
            None,
            None,
            fuel_core_types::fuel_types::ChainId::new(self.chain_id.unwrap_or_default()),
            None,
        )
    }
    pub fn original_transaction(&self) -> Result<Transaction, RlpError> {
        Self::fuel_tx_from_bytes(&self.original_tx_bytes)
    }
    pub fn original_transaction_wrapper(&self) -> Result<FuelTransaction, RlpError> {
        Ok(FuelTransaction::new(self.original_transaction()?))
    }
    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id
    }
    pub const fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    pub const fn tx_type(&self) -> TxType {
        TxType::FluentV1
    }
    pub const fn value(&self) -> &U256 {
        &U256::ZERO
    }
    pub const fn nonce(&self) -> u64 {
        0
    }
    pub const fn access_list(&self) -> Option<&AccessList> {
        self.access_list.as_ref()
    }
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub const fn is_dynamic_fee(&self) -> bool {
        false
    }
    pub const fn max_fee_per_gas(&self) -> u128 {
        MIN_PROTOCOL_BASE_FEE as u128
    }
    pub const fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }
    pub const fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }
    pub const fn priority_fee_or_price(&self) -> u128 {
        1
    }
    pub const fn effective_gas_price(&self, _base_fee: Option<u64>) -> u128 {
        1
    }
    pub const fn input(&self) -> &Bytes {
        &self.input
    }

    pub const fn tx_kind(&self) -> TxKind {
        // TODO use custom kind?
        self.tx_kind
    }

    pub fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        None
    }

    pub fn set_value(&mut self, _value: U256) {}
    pub fn set_nonce(&mut self, _nonce: u64) {}
    pub fn set_gas_limit(&mut self, _gas_limit: u64) {}
    pub fn set_input(&mut self, _input: Bytes) {}
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for FuelEnvironment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Implement arbitrary generation for FuelEnvironment
        todo!("Implement arbitrary for FuelEnvironment")
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::arbitrary::Arbitrary for FuelEnvironment {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Implement arbitrary strategy for FuelEnvironment
        todo!("Implement arbitrary strategy for FuelEnvironment")
    }

    fn arbitrary() -> Self::Strategy {
        Self::arbitrary_with(())
    }
}
