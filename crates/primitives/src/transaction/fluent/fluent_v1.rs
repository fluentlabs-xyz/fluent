use core::{fmt::Debug, mem};
use std::io::BufRead;

use alloy_eips::eip2930::AccessList;
use alloy_primitives::Address;
use alloy_rlp::{length_of_length, Decodable, Encodable, Error as RlpError, Header};
use bytes::{Buf, BufMut};
use fuel_core_types::fuel_types::canonical::Deserialize;
use fuel_tx::{
    field::{Inputs, Witnesses},
    Chargeable, UniqueIdentifier,
};
use proptest::prelude::*;

use crate::{
    hex,
    transaction::fluent::{fuel::FuelEnvironment, svm::SolanaEnvironment},
    Bytes, ChainId, Signature, TxKind, TxType, B256, U256,
};
use reth_codecs::{main_codec, Compact};

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

    pub fn from_str_with_data(env_type: &str, data: Bytes) -> Result<Self, RlpError> {
        let s = hex::decode(env_type).map_err(|v| RlpError::Custom("Invalid env type string"))?;
        ExecutionEnvironment::new(s[0], data)
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
    pub fn new(execution_environment: ExecutionEnvironment, data: Bytes) -> TxFluentV1 {
        Self { execution_environment, data }
    }

    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ExecutionEnvironment>() + // execution_environment
            mem::size_of::<Bytes>() + // data
            self.data.len()
    }

    pub(crate) fn fields_len(&self) -> usize {
        let data_len = self.data.len();
        // 1 for env type
        1 + length_of_length(data_len) + self.data.len()
    }

    pub(crate) fn payload_len(&self) -> usize {
        let fields_len = self.fields_len();
        length_of_length(fields_len) + fields_len
    }

    pub(crate) fn payload_len_for_signature(&self) -> usize {
        let payload_length = self.fields_len();
        // 'transaction type byte length' + 'header length' + 'payload length'
        1 + length_of_length(payload_length) + payload_length
    }

    pub(crate) fn payload_len_without_header(&self) -> usize {
        let payload_length = self.fields_len();
        1 + length_of_length(payload_length) + payload_length
    }

    pub(crate) fn encode_with_signature(
        &self,
        _signature: &Signature,
        out: &mut dyn BufMut,
        with_header: bool,
    ) {
        let payload_length = self.fields_len()/* + signature.payload_len()*/;

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
        // signature.encode(out);
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header.
    pub(crate) fn encode_fields(&self, out: &mut dyn BufMut) {
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
    pub(crate) fn payload_len_with_signature_without_header(
        &self,
        _signature: &Signature,
    ) -> usize {
        let payload_length = self.fields_len()
            /* + signature.payload_len()*/;
        // 'transaction type byte length' + 'header length' + 'payload length'
        1 + length_of_length(payload_length) + payload_length
    }

    pub(crate) const fn tx_type(&self) -> TxType {
        TxType::FluentV1
    }

    pub(crate) fn signature_hash(&self) -> B256 {
        B256::ZERO
    }

    pub(crate) fn recover_owner(&self) -> Option<fuel_core_types::fuel_types::Address> {
        match &self.execution_environment {
            ExecutionEnvironment::Fuel(ee) => {
                let Ok(transaction) = ee.original_transaction_wrapper() else { return None };
                let Some(chain_id) = ee.chain_id() else { return None };
                transaction.recover_first_owner(&chain_id.into()).map_or_else(|_| None, |a| Some(a))
            }
            ExecutionEnvironment::Solana(_) => None,
        }
    }

    pub(crate) fn hash(&self) -> Option<B256> {
        match &self.execution_environment {
            ExecutionEnvironment::Fuel(ee) => {
                let Ok(transaction) = ee.original_transaction_wrapper() else { return None };
                Some(B256::new(transaction.id(&ee.chain_id()?.into()).into()))
            }
            ExecutionEnvironment::Solana(_) => None,
        }
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
        1_000_000_000_u128
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
        let env_type = if let Some(v) = buf.first() {
            *v
        } else {
            return Err(RlpError::InputTooShort);
        };
        buf.advance(1);

        let header = Header::decode(buf)?;
        let data: Bytes = buf[..header.payload_length].to_vec().into();
        buf.advance(header.payload_length);

        let execution_environment = ExecutionEnvironment::new(env_type, data.clone())?;

        Ok(Self { execution_environment, data })
    }
}

impl Encodable for TxFluentV1 {
    fn encode(&self, out: &mut dyn BufMut) {
        // let header = Header { list: true, payload_length: 1 + self.data.len() };
        // header.encode(out);
        //
        // out.put_u8(self.execution_environment.env_type());
        // out.put_slice(&self.data);
        let mut buf = Vec::<u8>::with_capacity(1 + self.data.len());
        buf.push(self.execution_environment.env_type());
        buf.extend_from_slice(self.data.as_ref());
        buf.as_slice().encode(out);
    }

    fn length(&self) -> usize {
        // let payload_length = 1 + self.data.len();
        // let header = Header { list: true, payload_length };
        // header.length() + payload_length
        1 + self.data.len()
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
