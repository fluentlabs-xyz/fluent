use core::{fmt::Debug, mem};

use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::Address;
use alloy_rlp::{length_of_length, Decodable, Encodable, Error as RlpError, Header};
use bytes::BufMut;
use fluentbase_core::fvm::helpers::fuel_testnet_consensus_params_from;
use fuel_core_types::fuel_types::canonical::Deserialize;
use fuel_tx::{field::Inputs, Chargeable, ConsensusParameters};
use proptest::prelude::*;
use revm::handler::execution;

use crate::Signature;
use reth_codecs::{main_codec, Compact};

use crate::{Bytes, ChainId, TxKind, TxType, B256, U256};

/// Trait that must be implemented by each execution environment
trait IExecutionEnvironment {
    fn chain_id(&self) -> Option<ChainId>;
    fn tx_kind(&self) -> TxKind;
    fn value(&self) -> U256;
    fn set_value(&mut self, value: U256);
    fn nonce(&self) -> u64;
    fn set_nonce(&mut self, nonce: u64);
    fn gas_limit(&self) -> u64;
    fn set_gas_limit(&mut self, gas_limit: u64);
    fn max_fee_per_gas(&self) -> u128;
    fn max_priority_fee_per_gas(&self) -> Option<u128>;
    fn blob_versioned_hashes(&self) -> Option<Vec<B256>>;
    fn priority_fee_or_price(&self) -> u128;
    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128;
    fn input(&self) -> &Bytes;
    fn set_input(&mut self, input: Bytes);
}

#[derive(Debug, Clone, PartialEq, Eq, Compact, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ExecutionEnvironment {
    Fuel(FuelEnvironment) = 0,
    Solana(SolanaEnvironment) = 1,
}

impl From<ExecutionEnvironment> for u8 {
    fn from(env: ExecutionEnvironment) -> Self {
        match env {
            ExecutionEnvironment::Fuel(_) => 0,
            ExecutionEnvironment::Solana(_) => 1,
        }
    }
}

impl ExecutionEnvironment {
    pub fn new(env_type: u8, data: Bytes) -> Result<Self, RlpError> {
        match env_type {
            0 => Ok(ExecutionEnvironment::Fuel(FuelEnvironment::new(data)?)),
            1 => Ok(ExecutionEnvironment::Solana(SolanaEnvironment::new())),
            _ => Err(RlpError::Custom("Invalid execution environment type")),
        }
    }

    pub fn from_str_with_data(s: &str, data: Bytes) -> Result<Self, RlpError> {
        let s = s.trim_start_matches("0x");
        match s {
            "0" => ExecutionEnvironment::new(0, data),
            "1" => ExecutionEnvironment::new(1, data),
            _ => Err(RlpError::Custom("Invalid execution environment string")),
        }
    }

    pub fn env_type(&self) -> u8 {
        match self {
            ExecutionEnvironment::Fuel(_) => 0,
            ExecutionEnvironment::Solana(_) => 1,
        }
    }
}

impl Default for ExecutionEnvironment {
    fn default() -> Self {
        ExecutionEnvironment::Fuel(FuelEnvironment::default())
    }
}

impl ExecutionEnvironment {
    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            ExecutionEnvironment::Fuel(env) => env.set_chain_id(chain_id),
            ExecutionEnvironment::Solana(env) => env.set_chain_id(chain_id),
        }
    }
    const fn chain_id(&self) -> Option<ChainId> {
        match self {
            ExecutionEnvironment::Fuel(env) => env.chain_id(),
            ExecutionEnvironment::Solana(env) => env.chain_id(),
        }
    }

    const fn tx_kind(&self) -> TxKind {
        match self {
            ExecutionEnvironment::Fuel(env) => env.tx_kind(),
            ExecutionEnvironment::Solana(env) => env.tx_kind(),
        }
    }

    const fn value(&self) -> &U256 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.value(),
            ExecutionEnvironment::Solana(env) => env.value(),
        }
    }

    fn set_value(&mut self, value: U256) {
        match self {
            ExecutionEnvironment::Fuel(env) => env.set_value(value),
            ExecutionEnvironment::Solana(env) => env.set_value(value),
        }
    }

    pub const fn access_list(&self) -> Option<&AccessList> {
        match self {
            ExecutionEnvironment::Fuel(env) => env.access_list(),
            ExecutionEnvironment::Solana(env) => env.access_list(),
        }
    }

    pub const fn is_dynamic_fee(&self) -> bool {
        match self {
            ExecutionEnvironment::Fuel(env) => env.is_dynamic_fee(),
            ExecutionEnvironment::Solana(env) => env.is_dynamic_fee(),
        }
    }

    const fn nonce(&self) -> u64 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.nonce(),
            ExecutionEnvironment::Solana(env) => env.nonce(),
        }
    }

    fn set_nonce(&mut self, nonce: u64) {
        match self {
            ExecutionEnvironment::Fuel(env) => env.set_nonce(nonce),
            ExecutionEnvironment::Solana(env) => env.set_nonce(nonce),
        }
    }

    const fn gas_limit(&self) -> u64 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.gas_limit(),
            ExecutionEnvironment::Solana(env) => env.gas_limit(),
        }
    }

    fn set_gas_limit(&mut self, gas_limit: u64) {
        match self {
            ExecutionEnvironment::Fuel(env) => env.set_gas_limit(gas_limit),
            ExecutionEnvironment::Solana(env) => env.set_gas_limit(gas_limit),
        }
    }

    const fn max_fee_per_gas(&self) -> u128 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.max_fee_per_gas(),
            ExecutionEnvironment::Solana(env) => env.max_fee_per_gas(),
        }
    }

    const fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            ExecutionEnvironment::Fuel(env) => env.max_priority_fee_per_gas(),
            ExecutionEnvironment::Solana(env) => env.max_priority_fee_per_gas(),
        }
    }

    fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        match self {
            ExecutionEnvironment::Fuel(env) => env.blob_versioned_hashes(),
            ExecutionEnvironment::Solana(env) => env.blob_versioned_hashes(),
        }
    }

    pub const fn priority_fee_or_price(&self) -> u128 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.priority_fee_or_price(),
            ExecutionEnvironment::Solana(env) => env.priority_fee_or_price(),
        }
    }

    pub const fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match self {
            ExecutionEnvironment::Fuel(env) => env.effective_gas_price(base_fee),
            ExecutionEnvironment::Solana(env) => env.effective_gas_price(base_fee),
        }
    }

    pub const fn input(&self) -> &Bytes {
        match self {
            ExecutionEnvironment::Fuel(env) => env.input(),
            ExecutionEnvironment::Solana(env) => env.input(),
        }
    }

    fn set_input(&mut self, input: Bytes) {
        match self {
            ExecutionEnvironment::Fuel(env) => env.set_input(input),
            ExecutionEnvironment::Solana(env) => env.set_input(input),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ExecutionEnvironment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let env_type = <ExecutionEnvironment as arbitrary::Arbitrary>::arbitrary(u)?;
        match env_type {
            ExecutionEnvironment::Fuel(_) => Ok(ExecutionEnvironment::Fuel(
                <FuelEnvironment as arbitrary::Arbitrary>::arbitrary(u)?,
            )),
            ExecutionEnvironment::Solana(_) => Ok(ExecutionEnvironment::Solana(
                <SolanaEnvironment as arbitrary::Arbitrary>::arbitrary(u)?,
            )),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for ExecutionEnvironment {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<FuelEnvironment>().prop_map(ExecutionEnvironment::Fuel),
            any::<SolanaEnvironment>().prop_map(ExecutionEnvironment::Solana)
        ]
        .boxed()
    }

    fn arbitrary() -> Self::Strategy {
        Self::arbitrary_with(())
    }
}

#[main_codec]
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct TxFluentV1 {
    pub execution_environment: ExecutionEnvironment,
    pub data: Bytes,
}

impl TxFluentV1 {
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ExecutionEnvironment>() + // execution_environment
            mem::size_of::<Bytes>() + // data
            self.data.len()
    }

    fn fields_len(&self) -> usize {
        1 + // execution_environment type (u8 = 1 byte)
            length_of_length(self.data.len()) + self.data.len() // data + length
    }

    pub(crate) fn payload_len(&self) -> usize {
        let payload_length = self.fields_len();
        let len = 1 + length_of_length(payload_length) + payload_length;
        length_of_length(len) + len
    }

    pub(crate) fn payload_len_without_header(&self) -> usize {
        let payload_length = self.fields_len();
        1 + length_of_length(payload_length) + payload_length
    }

    pub(crate) fn encode_with_signature(
        &self,
        signature: &Signature,
        out: &mut dyn bytes::BufMut,
        with_header: bool,
    ) {
        let payload_length = self.fields_len() + signature.payload_len();

        if with_header {
            Header {
                list: false,
                payload_length: 1 + length_of_length(payload_length) + payload_length,
            }
            .encode(out);
        }

        out.put_u8(self.tx_type() as u8);

        let header = Header { list: true, payload_length };
        header.encode(out);

        self.encode_fields(out);
        signature.encode(out);
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header.
    pub(crate) fn encode_fields(&self, out: &mut dyn bytes::BufMut) {
        // Encode the execution environment as a single byte
        out.put_u8(self.execution_environment.env_type());

        // Encode the data
        self.data.encode(out);
    }

    /// Output the length of the RLP signed transaction encoding. This encodes with a RLP header.
    pub(crate) fn payload_len_with_signature(&self, signature: &Signature) -> usize {
        let len = self.payload_len_with_signature_without_header(signature);
        length_of_length(len) + len
    }
    /// Output the length of the RLP signed transaction encoding, _without_ a RLP string header.
    pub(crate) fn payload_len_with_signature_without_header(&self, signature: &Signature) -> usize {
        let payload_length = self.fields_len() + signature.payload_len();
        // 'transaction type byte length' + 'header length' + 'payload length'
        1 + length_of_length(payload_length) + payload_length
    }

    pub(crate) const fn tx_type(&self) -> TxType {
        TxType::FluentV1
    }

    pub(crate) fn signature_hash(&self) -> B256 {
        B256::ZERO
    }

    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.execution_environment.set_chain_id(chain_id)
    }

    pub(crate) const fn chain_id(&self) -> Option<ChainId> {
        self.execution_environment.chain_id()
    }

    pub(crate) const fn tx_kind(&self) -> TxKind {
        self.execution_environment.tx_kind()
    }

    pub const fn value(&self) -> &U256 {
        self.execution_environment.value()
    }

    pub fn set_value(&mut self, value: U256) {
        self.execution_environment.set_value(value)
    }

    pub const fn nonce(&self) -> u64 {
        self.execution_environment.nonce()
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.execution_environment.set_nonce(nonce)
    }

    pub const fn gas_limit(&self) -> u64 {
        self.execution_environment.gas_limit()
    }

    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.execution_environment.set_gas_limit(gas_limit)
    }

    pub const fn max_fee_per_gas(&self) -> u128 {
        self.execution_environment.max_fee_per_gas()
    }

    pub const fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.execution_environment.max_priority_fee_per_gas()
    }

    pub fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        self.execution_environment.blob_versioned_hashes()
    }

    pub const fn priority_fee_or_price(&self) -> u128 {
        self.execution_environment.priority_fee_or_price()
    }

    pub const fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.execution_environment.effective_gas_price(base_fee)
    }

    pub const fn is_dynamic_fee(&self) -> bool {
        self.execution_environment.is_dynamic_fee()
    }
    pub fn gas_price(&self) -> u128 {
        todo!()
    }

    pub const fn access_list(&self) -> Option<&AccessList> {
        self.execution_environment.access_list()
    }

    pub const fn input(&self) -> &Bytes {
        self.execution_environment.input()
    }

    pub fn set_input(&mut self, input: Bytes) {
        self.execution_environment.set_input(input)
    }

    pub(crate) fn decode_inner(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        if buf.is_empty() {
            return Err(RlpError::InputTooShort);
        }

        let env_type = buf[0];
        *buf = &buf[1..];

        let data: Bytes = Decodable::decode(buf)?;

        let execution_environment = ExecutionEnvironment::new(env_type, data.clone())?;

        Ok(Self { execution_environment, data })
    }
}

impl Encodable for TxFluentV1 {
    fn encode(&self, out: &mut dyn BufMut) {
        let header = Header { list: true, payload_length: 1 + self.data.len() };
        header.encode(out);

        out.put_u8(self.execution_environment.env_type());
        out.put_slice(&self.data);
    }

    fn length(&self) -> usize {
        let payload_length = 1 + self.data.len();
        let header = Header { list: true, payload_length };
        header.length() + payload_length
    }
}

impl Decodable for TxFluentV1 {
    fn decode(buf: &mut &[u8]) -> Result<Self, RlpError> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(RlpError::Custom("Expected list"));
        }

        let env_type = <u8 as Decodable>::decode(buf)?;
        let data = Bytes::decode(buf)?;

        let execution_environment = ExecutionEnvironment::new(env_type, data.clone())?;

        Ok(TxFluentV1 { execution_environment, data })
    }
}

pub struct FuelTransaction(fuel_tx::Transaction);
impl FuelTransaction {
    pub fn inputs(&self) -> Result<&Vec<fuel_tx::Input>, alloy_rlp::Error> {
        match &self.0 {
            fuel_tx::Transaction::Script(t) => Ok(t.inputs()),
            fuel_tx::Transaction::Create(t) => Ok(t.inputs()),
            fuel_tx::Transaction::Upgrade(t) => Ok(t.inputs()),
            fuel_tx::Transaction::Upload(t) => Ok(t.inputs()),
            fuel_tx::Transaction::Mint(t) => Err(alloy_rlp::Error::Custom("mint tx unsupported")),
        }
    }
    pub fn gas_limit(&self, cp: &ConsensusParameters) -> Result<u64, alloy_rlp::Error> {
        match &self.0 {
            fuel_tx::Transaction::Script(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            fuel_tx::Transaction::Create(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            fuel_tx::Transaction::Upgrade(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            fuel_tx::Transaction::Upload(t) => Ok(t.max_gas(cp.gas_costs(), cp.fee_params())),
            fuel_tx::Transaction::Mint(_) => Err(alloy_rlp::Error::Custom("mint tx unsupported")),
        }
    }
}

#[derive(
    Debug, Default, Clone, PartialEq, Eq, Hash, Compact, serde::Serialize, serde::Deserialize,
)]
pub struct FuelEnvironment {
    original_tx_bytes: Vec<u8>,
    chain_id: Option<ChainId>,
    access_list: Option<AccessList>,
    gas_limit: u64,
    tx_kind: TxKind,
    input: Bytes,
}

impl FuelEnvironment {
    pub fn new(data: Bytes) -> Result<Self, RlpError> {
        let tx: fuel_tx::Transaction = fuel_tx::Transaction::from_bytes(&data.as_ref())
            .map_err(|e| RlpError::Custom(&"failed to parse fuel tx"))?;
        let original_tx = FuelTransaction(tx);
        let consensus_params = fuel_testnet_consensus_params_from(
            None,
            None,
            None,
            fuel_core_types::fuel_types::ChainId::new(0),
            None,
        );
        let mut alt = Vec::<AccessListItem>::new();
        for input in original_tx.inputs()? {
            let owner = input.input_owner();
            if let Some(owner) = owner {
                alt.push(AccessListItem {
                    address: Address::from_slice(&owner[12..]),
                    storage_keys: Default::default(),
                });
            }
        }
        let instance = Self {
            original_tx_bytes: data.to_vec(),
            chain_id: Some(ChainId::from(consensus_params.chain_id())),
            access_list: Some(AccessList(alt)),
            gas_limit: original_tx
                .gas_limit(&consensus_params)
                .map_err(|e| RlpError::Custom("failed to get gas limit from tx"))?,
            // TODO
            tx_kind: TxKind::Create,
            ..Default::default()
        };

        Ok(instance)
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
        1
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

    fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        None
    }

    fn set_value(&mut self, _value: U256) {}
    fn set_nonce(&mut self, _nonce: u64) {}
    fn set_gas_limit(&mut self, _gas_limit: u64) {}
    fn set_input(&mut self, _input: Bytes) {}
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
    fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        None
    }
    fn set_value(&mut self, value: U256) {
        self.value = value;
    }
    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.gas_limit = gas_limit;
    }
    fn set_input(&mut self, input: Bytes) {
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
        todo!("Implement arbitrary strategy for SolanaEnvironment")
    }

    fn arbitrary() -> Self::Strategy {
        Self::arbitrary_with(())
    }
}
