use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{keccak256, B256, U256};
use fluentbase_genesis::devnet::GENESIS_KECCAK_HASH_SLOT;
use fluentbase_poseidon::poseidon_hash;
use reth_codecs::{main_codec, Compact};
use std::ops::Deref;

/// An Ethereum account.
#[main_codec]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Account {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Hash of the account's bytecode.
    pub bytecode_hash: Option<B256>,
    // /// Hash of the rWASM bytecode
    // pub rwasm_hash: Option<B256>,
}

impl Account {
    /// Whether the account has bytecode.
    pub const fn has_bytecode(&self) -> bool {
        self.bytecode_hash.is_some()
    }

    /// After `SpuriousDragon` empty account is defined as account with nonce == 0 && balance == 0
    /// && bytecode = None (or hash is [`KECCAK_EMPTY`]).
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 &&
            self.balance.is_zero() &&
            self.bytecode_hash.map_or(true, |hash| hash == KECCAK_EMPTY)
    }

    /// Makes an [Account] from [`GenesisAccount`] type
    pub fn from_genesis_account(value: &GenesisAccount) -> Self {
        // let bytecode_hash = value.storage
        //     .as_ref()
        //     .and_then(|s| s.get(&GENESIS_KECCAK_HASH_SLOT))
        //     .cloned()
        //     .or_else(|| {
        //         value.code.as_ref().map(|bytes| keccak256(bytes.as_ref()))
        //     });
        // let rwasm_hash =
        //     value.storage.as_ref().and_then(|s|
        // s.get(&GENESIS_KECCAK_HASH_SLOT)).cloned().or_else(         ||
        // value.code.as_ref().map(|bytes| B256::from(poseidon_hash(bytes.as_ref()))),
        //     );
        Self {
            // nonce must exist, so we default to zero when converting a genesis account
            nonce: value.nonce.unwrap_or_default(),
            balance: value.balance,
            bytecode_hash: value.code.as_ref().map(keccak256),
            // rwasm_hash,
        }
    }

    /// Returns an account bytecode's hash.
    /// In case of no bytecode, returns [`KECCAK_EMPTY`].
    pub fn get_bytecode_hash(&self) -> B256 {
        self.bytecode_hash.unwrap_or(KECCAK_EMPTY)
    }
}
