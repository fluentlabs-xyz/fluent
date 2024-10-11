use crate::{revm_primitives::{AccountInfo, POSEIDON_EMPTY}, Account, Address, TxKind, KECCAK_EMPTY, U256};
use revm::{interpreter::gas::validate_initial_tx_gas, primitives::SpecId};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Converts a Revm [`AccountInfo`] into a Reth [`Account`].
///
/// Sets `bytecode_hash` to `None` if `code_hash` is [`KECCAK_EMPTY`].
pub fn into_reth_acc(revm_acc: AccountInfo) -> Account {
    Account {
        balance: revm_acc.balance,
        nonce: revm_acc.nonce,
        bytecode_hash: (!revm_acc.is_empty_code_hash()).then_some(revm_acc.code_hash),
    }
}

/// Converts a Revm [`AccountInfo`] into a Reth [`Account`].
///
/// Sets `code_hash` to [`KECCAK_EMPTY`] if `bytecode_hash` is `None`.
pub fn into_revm_acc(reth_acc: Account) -> AccountInfo {
    AccountInfo {
        balance: reth_acc.balance,
        nonce: reth_acc.nonce,
        code_hash: reth_acc.bytecode_hash.unwrap_or(if cfg!(feature = "rwasm") {
            POSEIDON_EMPTY
        } else {
            KECCAK_EMPTY
        }),
        code: None,
    }
}

/// Calculates the Intrinsic Gas usage for a Transaction
///
/// Caution: This only checks past the Merge hardfork.
#[inline]
pub fn calculate_intrinsic_gas_after_merge(
    input: &[u8],
    kind: &TxKind,
    access_list: &[(Address, Vec<U256>)],
    is_shanghai: bool,
) -> u64 {
    let spec_id = if is_shanghai { SpecId::SHANGHAI } else { SpecId::MERGE };
    validate_initial_tx_gas(spec_id, input, kind.is_create(), access_list)
}
