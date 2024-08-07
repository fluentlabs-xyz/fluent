use core::{default, fmt::Debug, mem};

use alloy_eips::eip2930::AccessList;
use alloy_primitives::Address;
use alloy_rlp::{length_of_length, Decodable, Encodable, Error as RlpError, Error, Header};
use bytes::BufMut;
use proptest::prelude::*;
use revm::handler::execution;

use crate::{Signature, TxLegacy};
use reth_codecs::{main_codec, Compact};

use crate::{Bytes, ChainId, TxKind, TxType, B256, U256};

/// Version 2 of the Fluent transaction type.
#[main_codec]
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct TxFluentV1 {
    /// The transaction's fields that are common to all transaction types.
    /// This includes the chain ID, nonce, gas price, gas limit, recipient, value, and input data.
    /// If some values are not applicable to the transaction type, they should be set to zero.
    pub eth_fields: TxLegacy,

    /// The transaction's execution environment, Fuel/Solana. EVM transactions are using classic
    /// EVM tx types.
    pub execution_environment: ExecutionEnvironment,

    /// Execution environment's native transaction represented as a byte array.
    pub native_tx: Bytes,
}

impl TxFluentV1 {
    pub fn new(
        eth_fields: TxLegacy,
        execution_environment: ExecutionEnvironment,
        native_tx: Bytes,
    ) -> Self {
        Self { eth_fields, execution_environment, native_tx }
    }
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ExecutionEnvironment>() + // execution_environment
            mem::size_of::<Bytes>() + // len of len
            self.eth_fields.size() + // eth_fields
            self.native_tx.len()
    }

    fn fields_len(&self) -> usize {
        1 + // execution_environment type (u8 = 1 byte)
            self.eth_fields.fields_len() + // eth_fields
            length_of_length(self.native_tx.len()) + self.native_tx.len()
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
        out.put_u8(self.execution_environment.clone() as u8);

        self.eth_fields.encode_fields(out);

        // Encode the data
        self.native_tx.encode(out);
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
    pub(crate) fn signature_hash(&self) -> B256 {
        B256::ZERO
    }
    pub const fn chain_id(&self) -> Option<ChainId> {
        self.eth_fields.chain_id
    }
    pub const fn kind(&self) -> TxKind {
        self.eth_fields.to
    }
    pub const fn tx_type(&self) -> TxType {
        TxType::FluentV1
    }
    pub const fn value(&self) -> &U256 {
        &self.eth_fields.value
    }
    pub const fn nonce(&self) -> u64 {
        self.eth_fields.nonce
    }
    pub const fn access_list(&self) -> Option<&AccessList> {
        None
    }
    pub const fn gas_limit(&self) -> u64 {
        self.eth_fields.gas_limit
    }
    pub const fn is_dynamic_fee(&self) -> bool {
        false
    }
    pub const fn max_fee_per_gas(&self) -> u128 {
        0
    }
    pub const fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }

    pub const fn gas_price(&self) -> u128 {
        self.eth_fields.gas_price
    }

    pub const fn priority_fee_or_price(&self) -> u128 {
        self.eth_fields.gas_price
    }
    pub const fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.eth_fields.gas_price
    }
    pub const fn input(&self) -> &Bytes {
        &self.eth_fields.input
    }
    pub const fn tx_kind(&self) -> TxKind {
        self.eth_fields.to
    }
    pub fn blob_versioned_hashes(&self) -> Option<Vec<B256>> {
        None
    }
    pub fn set_value(&mut self, value: U256) {
        self.eth_fields.value = value;
    }
    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.eth_fields.chain_id = chain_id;
    }
    pub fn set_nonce(&mut self, nonce: u64) {
        self.eth_fields.nonce = nonce;
    }
    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.eth_fields.gas_limit = gas_limit;
    }
    pub fn set_input(&mut self, input: Bytes) {
        self.eth_fields.input = input;
    }
}

impl Encodable for TxFluentV1 {
    fn encode(&self, out: &mut dyn BufMut) {
        let header = Header {
            list: true,
            payload_length: 1 + self.native_tx.len() + self.eth_fields.size(),
        };
        header.encode(out);

        out.put_u8(self.execution_environment.clone() as u8);

        self.eth_fields.encode_fields(out);
        out.put_slice(&self.native_tx);
    }

    fn length(&self) -> usize {
        let payload_length = 1 + self.native_tx.len() + self.eth_fields.size();
        let header = Header { list: true, payload_length };
        header.length() + payload_length
    }
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, Compact, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum ExecutionEnvironment {
    #[default]
    Fuel = 0,
    Solana = 1,
}

impl From<u8> for ExecutionEnvironment {
    fn from(value: u8) -> Self {
        match value {
            0 => ExecutionEnvironment::Fuel,
            1 => ExecutionEnvironment::Solana,
            _ => panic!("Invalid value for ExecutionEnvironment"),
        }
    }
}

impl From<ExecutionEnvironment> for u8 {
    fn from(env: ExecutionEnvironment) -> Self {
        env as u8
    }
}

impl ExecutionEnvironment {
    // TODO: d1r1 we need to validate native tx before we passes it to the blended API endpoint
    // to avoid ddos attacks and other possible issues
    pub fn validate_tx(&self, native_tx: Bytes) -> Result<(), String> {
        match self {
            ExecutionEnvironment::Fuel => todo!(),
            ExecutionEnvironment::Solana => todo!(),
        }
    }
    // also we need to implement decoding and encoding of the native tx
    pub fn decode_tx(&self, buf: &mut &[u8]) -> Result<TxFluentV1, Error> {
        match self {
            ExecutionEnvironment::Fuel => todo!(),
            ExecutionEnvironment::Solana => todo!(),
        }
    }
    pub fn encode_tx(&self, tx: &TxFluentV1, out: &mut dyn bytes::BufMut) {
        match self {
            ExecutionEnvironment::Fuel => todo!(),
            ExecutionEnvironment::Solana => todo!(),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ExecutionEnvironment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let env_type = <ExecutionEnvironment as arbitrary::Arbitrary>::arbitrary(u)?;
        match env_type {
            ExecutionEnvironment::Fuel => Ok(ExecutionEnvironment::Fuel),
            ExecutionEnvironment::Solana => Ok(ExecutionEnvironment::Solana),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::arbitrary::Arbitrary for ExecutionEnvironment {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(ExecutionEnvironment::Fuel), Just(ExecutionEnvironment::Solana)].boxed()
    }

    fn arbitrary() -> Self::Strategy {
        Self::arbitrary_with(())
    }
}
