//! utilities for working with revm

use crate::eth::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use alloy_primitives::Bytes;
#[cfg(feature = "optimism")]
use reth_primitives::revm::env::fill_op_tx_env;
#[cfg(not(feature = "optimism"))]
use reth_primitives::revm::env::fill_tx_env;
use reth_primitives::{
    revm::env::fill_tx_env_with_recovered, Address, TransactionSigned,
    TransactionSignedEcRecovered, TxHash, TxKind, B256, U256,
};
use reth_rpc_types::{
    state::{AccountOverride, EvmOverrides, StateOverride},
    BlockOverrides, TransactionRequest,
};
#[cfg(feature = "optimism")]
use revm::primitives::OptimismFields;
use revm::{
    db::CacheDB,
    precompile::{PrecompileSpecId, Precompiles},
    primitives::{
        db::DatabaseRef, BlockEnv, Bytecode, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, SpecId,
        TransactTo, TxEnv,
    },
    Database,
};
use revm_primitives::ExecutionEnvironment;
use std::{cmp::min, iter};
use tracing::trace;

/// Helper type to work with different transaction types when configuring the EVM env.
///
/// This makes it easier to handle errors.
pub trait FillableTransaction {
    /// Returns the hash of the transaction.
    fn hash(&self) -> TxHash;

    /// Fill the transaction environment with the given transaction.
    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()>;
}

impl FillableTransaction for TransactionSignedEcRecovered {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()> {
        #[cfg(not(feature = "optimism"))]
        fill_tx_env_with_recovered(tx_env, self);

        #[cfg(feature = "optimism")]
        {
            let mut envelope_buf = Vec::with_capacity(self.length_without_header());
            self.encode_enveloped(&mut envelope_buf);
            fill_tx_env_with_recovered(tx_env, self, envelope_buf.into());
        }
        Ok(())
    }
}
impl FillableTransaction for TransactionSigned {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()> {
        let signer =
            self.recover_signer().ok_or_else(|| EthApiError::InvalidTransactionSignature)?;
        #[cfg(not(feature = "optimism"))]
        fill_tx_env(tx_env, self, signer);

        #[cfg(feature = "optimism")]
        {
            let mut envelope_buf = Vec::with_capacity(self.length_without_header());
            self.encode_enveloped(&mut envelope_buf);
            fill_op_tx_env(tx_env, self, signer, envelope_buf.into());
        }
        Ok(())
    }
}

/// Returns the addresses of the precompiles corresponding to the `SpecId`.
#[inline]
pub fn get_precompiles(_spec_id: SpecId) -> impl IntoIterator<Item = Address> {
    iter::empty()
    // let spec = PrecompileSpecId::from_spec_id(spec_id);
    // Precompiles::new(spec).addresses().copied().map(Address::from)
}

/// Prepares the [`EnvWithHandlerCfg`] for execution.
///
/// Does not commit any changes to the underlying database.
///
/// EVM settings:
///  - `disable_block_gas_limit` is set to `true`
///  - `disable_eip3607` is set to `true`
///  - `disable_base_fee` is set to `true`
///  - `nonce` is set to `None`
pub fn prepare_call_env<DB>(
    mut cfg: CfgEnvWithHandlerCfg,
    mut block: BlockEnv,
    request: TransactionRequest,
    gas_limit: u64,
    db: &mut CacheDB<DB>,
    overrides: EvmOverrides,
) -> EthResult<EnvWithHandlerCfg>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    // we want to disable this in eth_call, since this is common practice used by other node
    // impls and providers <https://github.com/foundry-rs/foundry/issues/4388>
    cfg.disable_block_gas_limit = true;

    // Disabled because eth_call is sometimes used with eoa senders
    // See <https://github.com/paradigmxyz/reth/issues/1959>
    cfg.disable_eip3607 = true;

    // The basefee should be ignored for eth_call
    // See:
    // <https://github.com/ethereum/go-ethereum/blob/ee8e83fa5f6cb261dad2ed0a7bbcde4930c41e6c/internal/ethapi/api.go#L985>
    cfg.disable_base_fee = true;

    // apply block overrides, we need to apply them first so that they take effect when we we create
    // the evm env via `build_call_evm_env`, e.g. basefee
    if let Some(mut block_overrides) = overrides.block {
        if let Some(block_hashes) = block_overrides.block_hash.take() {
            // override block hashes
            db.block_hashes
                .extend(block_hashes.into_iter().map(|(num, hash)| (U256::from(num), hash)))
        }
        apply_block_overrides(*block_overrides, &mut block);
    }

    let request_gas = request.gas;
    let mut env = build_call_evm_env(cfg, block, request)?;
    // set nonce to None so that the next nonce is used when transacting the call
    env.tx.nonce = None;

    // apply state overrides
    if let Some(state_overrides) = overrides.state {
        apply_state_overrides(state_overrides, db)?;
    }

    if request_gas.is_none() {
        // No gas limit was provided in the request, so we need to cap the transaction gas limit
        if env.tx.gas_price > U256::ZERO {
            // If gas price is specified, cap transaction gas limit with caller allowance
            trace!(target: "rpc::eth::call", ?env, "Applying gas limit cap with caller allowance");
            cap_tx_gas_limit_with_caller_allowance(db, &mut env.tx)?;
        } else {
            // If no gas price is specified, use maximum allowed gas limit. The reason for this is
            // that both Erigon and Geth use pre-configured gas cap even if it's possible
            // to derive the gas limit from the block:
            // <https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/cmd/rpcdaemon/commands/trace_adhoc.go#L956
            // https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/eth/ethconfig/config.go#L94>
            trace!(target: "rpc::eth::call", ?env, "Applying gas limit cap as the maximum gas limit");
            env.tx.gas_limit = gas_limit;
        }
    }

    Ok(env)
}

/// Creates a new [`EnvWithHandlerCfg`] to be used for executing the [`TransactionRequest`] in
/// `eth_call`.
///
/// Note: this does _not_ access the Database to check the sender.
pub fn build_call_evm_env(
    cfg: CfgEnvWithHandlerCfg,
    block: BlockEnv,
    request: TransactionRequest,
) -> EthResult<EnvWithHandlerCfg> {
    let tx = create_txn_env(&block, request)?;
    Ok(EnvWithHandlerCfg::new_with_cfg_env(cfg, block, tx))
}

/// Configures a new [`TxEnv`]  for the [`TransactionRequest`]
///
/// All [`TxEnv`] fields are derived from the given [`TransactionRequest`], if fields are `None`,
/// they fall back to the [`BlockEnv`]'s settings.
pub fn create_txn_env(block_env: &BlockEnv, request: TransactionRequest) -> EthResult<TxEnv> {
    // Ensure that if versioned hashes are set, they're not empty
    if request.blob_versioned_hashes.as_ref().map_or(false, |hashes| hashes.is_empty()) {
        return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into())
    }

    let TransactionRequest {
        from,
        to,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas,
        value,
        input,
        nonce,
        access_list,
        chain_id,
        blob_versioned_hashes,
        max_fee_per_blob_gas,
        transaction_type,
        ..
    } = request;

    let CallFees { max_priority_fee_per_gas, gas_price, max_fee_per_blob_gas } =
        CallFees::ensure_fees(
            gas_price.map(U256::from),
            max_fee_per_gas.map(U256::from),
            max_priority_fee_per_gas.map(U256::from),
            block_env.basefee,
            blob_versioned_hashes.as_deref(),
            max_fee_per_blob_gas.map(U256::from),
            block_env.get_blob_gasprice().map(U256::from),
        )?;

    let gas_limit = gas.unwrap_or_else(|| block_env.gas_limit.min(U256::from(u64::MAX)).to());
    // let transact_to = {
    //     if let Some(transaction_type) = transaction_type {
    //         let Some(data) = input.data.clone() else {
    //             return Err(EthApiError::EvmCustom(
    //                 "data field must be provided when tx type set".to_string(),
    //             ))
    //         };
    //         match transaction_type {
    //             5 => TransactTo::Blended(ExecutionEnvironment::Fuel, data),
    //             6 => TransactTo::Blended(ExecutionEnvironment::Solana, data),
    //             _ => {
    //                 return Err(EthApiError::EvmCustom(
    //                     "unsupported transaction_type={}. only 5 (Fuel) and 6
    // (Solana)".to_string(),                 ))
    //             }
    //         }
    //         // Transaction::FluentV1
    //     } else {
    //         match to {
    //             Some(TxKind::Call(to)) => TransactTo::call(to),
    //             _ => TransactTo::create(),
    //         }
    //     }
    // };
    let transact_to = match to {
        Some(TxKind::Call(to)) => TransactTo::call(to),
        _ => TransactTo::create(),
    };
    let env = TxEnv {
        gas_limit: gas_limit.try_into().map_err(|_| RpcInvalidTransactionError::GasUintOverflow)?,
        nonce,
        caller: from.unwrap_or_default(),
        gas_price,
        gas_priority_fee: max_priority_fee_per_gas,
        transact_to,
        value: value.unwrap_or_default(),
        data: input.try_into_unique_input()?.unwrap_or_default(),
        chain_id,
        access_list: access_list
            .map(reth_rpc_types::AccessList::into_flattened)
            .unwrap_or_default(),
        // EIP-4844 fields
        blob_hashes: blob_versioned_hashes.unwrap_or_default(),
        max_fee_per_blob_gas,
        #[cfg(feature = "optimism")]
        optimism: OptimismFields { enveloped_tx: Some(Bytes::new()), ..Default::default() },
    };

    Ok(env)
}

/// Caps the configured [`TxEnv`] `gas_limit` with the allowance of the caller.
pub fn cap_tx_gas_limit_with_caller_allowance<DB>(db: &mut DB, env: &mut TxEnv) -> EthResult<()>
where
    DB: Database,
    EthApiError: From<<DB as Database>::Error>,
{
    if let Ok(gas_limit) = caller_gas_allowance(db, env)?.try_into() {
        env.gas_limit = gas_limit;
    }

    Ok(())
}

/// Calculates the caller gas allowance.
///
/// `allowance = (account.balance - tx.value) / tx.gas_price`
///
/// Returns an error if the caller has insufficient funds.
/// Caution: This assumes non-zero `env.gas_price`. Otherwise, zero allowance will be returned.
pub fn caller_gas_allowance<DB>(db: &mut DB, env: &TxEnv) -> EthResult<U256>
where
    DB: Database,
    EthApiError: From<<DB as Database>::Error>,
{
    Ok(db
        // Get the caller account.
        .basic(env.caller)?
        // Get the caller balance.
        .map(|acc| acc.balance)
        .unwrap_or_default()
        // Subtract transferred value from the caller balance.
        .checked_sub(env.value)
        // Return error if the caller has insufficient funds.
        .ok_or_else(|| RpcInvalidTransactionError::InsufficientFunds)?
        // Calculate the amount of gas the caller can afford with the specified gas price.
        .checked_div(env.gas_price)
        // This will be 0 if gas price is 0. It is fine, because we check it before.
        .unwrap_or_default())
}

/// Helper type for representing the fees of a [`TransactionRequest`]
#[derive(Debug)]
pub struct CallFees {
    /// EIP-1559 priority fee
    max_priority_fee_per_gas: Option<U256>,
    /// Unified gas price setting
    ///
    /// Will be the configured `basefee` if unset in the request
    ///
    /// `gasPrice` for legacy,
    /// `maxFeePerGas` for EIP-1559
    gas_price: U256,
    /// Max Fee per Blob gas for EIP-4844 transactions
    max_fee_per_blob_gas: Option<U256>,
}

// === impl CallFees ===

impl CallFees {
    /// Ensures the fields of a [`TransactionRequest`] are not conflicting.
    ///
    /// # EIP-4844 transactions
    ///
    /// Blob transactions have an additional fee parameter `maxFeePerBlobGas`.
    /// If the `maxFeePerBlobGas` or `blobVersionedHashes` are set we treat it as an EIP-4844
    /// transaction.
    ///
    /// Note: Due to the `Default` impl of [`BlockEnv`] (Some(0)) this assumes the `block_blob_fee`
    /// is always `Some`
    fn ensure_fees(
        call_gas_price: Option<U256>,
        call_max_fee: Option<U256>,
        call_priority_fee: Option<U256>,
        block_base_fee: U256,
        blob_versioned_hashes: Option<&[B256]>,
        max_fee_per_blob_gas: Option<U256>,
        block_blob_fee: Option<U256>,
    ) -> EthResult<Self> {
        /// Get the effective gas price of a transaction as specfified in EIP-1559 with relevant
        /// checks.
        fn get_effective_gas_price(
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            block_base_fee: U256,
        ) -> EthResult<U256> {
            match max_fee_per_gas {
                Some(max_fee) => {
                    if max_fee < block_base_fee {
                        // `base_fee_per_gas` is greater than the `max_fee_per_gas`
                        return Err(RpcInvalidTransactionError::FeeCapTooLow.into())
                    }
                    if max_fee < max_priority_fee_per_gas.unwrap_or(U256::ZERO) {
                        return Err(
                            // `max_priority_fee_per_gas` is greater than the `max_fee_per_gas`
                            RpcInvalidTransactionError::TipAboveFeeCap.into(),
                        )
                    }
                    Ok(min(
                        max_fee,
                        block_base_fee
                            .checked_add(max_priority_fee_per_gas.unwrap_or(U256::ZERO))
                            .ok_or_else(|| {
                                EthApiError::from(RpcInvalidTransactionError::TipVeryHigh)
                            })?,
                    ))
                }
                None => Ok(block_base_fee
                    .checked_add(max_priority_fee_per_gas.unwrap_or(U256::ZERO))
                    .ok_or_else(|| EthApiError::from(RpcInvalidTransactionError::TipVeryHigh))?),
            }
        }

        let has_blob_hashes =
            blob_versioned_hashes.as_ref().map(|blobs| !blobs.is_empty()).unwrap_or(false);

        match (call_gas_price, call_max_fee, call_priority_fee, max_fee_per_blob_gas) {
            (gas_price, None, None, None) => {
                // either legacy transaction or no fee fields are specified
                // when no fields are specified, set gas price to zero
                let gas_price = gas_price.unwrap_or(U256::ZERO);
                Ok(Self {
                    gas_price,
                    max_priority_fee_per_gas: None,
                    max_fee_per_blob_gas: has_blob_hashes.then_some(block_blob_fee).flatten(),
                })
            }
            (None, max_fee_per_gas, max_priority_fee_per_gas, None) => {
                // request for eip-1559 transaction
                let effective_gas_price = get_effective_gas_price(
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    block_base_fee,
                )?;
                let max_fee_per_blob_gas = has_blob_hashes.then_some(block_blob_fee).flatten();

                Ok(Self {
                    gas_price: effective_gas_price,
                    max_priority_fee_per_gas,
                    max_fee_per_blob_gas,
                })
            }
            (None, max_fee_per_gas, max_priority_fee_per_gas, Some(max_fee_per_blob_gas)) => {
                // request for eip-4844 transaction
                let effective_gas_price = get_effective_gas_price(
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    block_base_fee,
                )?;
                // Ensure blob_hashes are present
                if !has_blob_hashes {
                    // Blob transaction but no blob hashes
                    return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into())
                }

                Ok(Self {
                    gas_price: effective_gas_price,
                    max_priority_fee_per_gas,
                    max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
                })
            }
            _ => {
                // this fallback covers incompatible combinations of fields
                Err(EthApiError::ConflictingFeeFieldsInRequest)
            }
        }
    }
}

/// Applies the given block overrides to the env
fn apply_block_overrides(overrides: BlockOverrides, env: &mut BlockEnv) {
    let BlockOverrides {
        number,
        difficulty,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash: _,
    } = overrides;

    if let Some(number) = number {
        env.number = number;
    }
    if let Some(difficulty) = difficulty {
        env.difficulty = difficulty;
    }
    if let Some(time) = time {
        env.timestamp = U256::from(time);
    }
    if let Some(gas_limit) = gas_limit {
        env.gas_limit = U256::from(gas_limit);
    }
    if let Some(coinbase) = coinbase {
        env.coinbase = coinbase;
    }
    if let Some(random) = random {
        env.prevrandao = Some(random);
    }
    if let Some(base_fee) = base_fee {
        env.basefee = base_fee;
    }
}

/// Applies the given state overrides (a set of [`AccountOverride`]) to the [`CacheDB`].
pub fn apply_state_overrides<DB>(overrides: StateOverride, db: &mut CacheDB<DB>) -> EthResult<()>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    for (account, account_overrides) in overrides {
        apply_account_override(account, account_overrides, db)?;
    }
    Ok(())
}

/// Applies a single [`AccountOverride`] to the [`CacheDB`].
fn apply_account_override<DB>(
    account: Address,
    account_override: AccountOverride,
    db: &mut CacheDB<DB>,
) -> EthResult<()>
where
    DB: DatabaseRef,
    EthApiError: From<<DB as DatabaseRef>::Error>,
{
    // we need to fetch the account via the `DatabaseRef` to not update the state of the account,
    // which is modified via `Database::basic_ref`
    let mut account_info = DatabaseRef::basic_ref(db, account)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        account_info.nonce = nonce.to();
    }
    if let Some(code) = account_override.code {
        account_info.code = Some(Bytecode::new_raw(code));
    }
    if let Some(balance) = account_override.balance {
        account_info.balance = balance;
    }

    db.insert_account_info(account, account_info);

    // We ensure that not both state and state_diff are set.
    // If state is set, we must mark the account as "NewlyCreated", so that the old storage
    // isn't read from
    match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(EthApiError::BothStateAndStateDiffInOverride(account)),
        (None, None) => {
            // nothing to do
        }
        (Some(new_account_state), None) => {
            db.replace_account_storage(
                account,
                new_account_state
                    .into_iter()
                    .map(|(slot, value)| {
                        (U256::from_be_bytes(slot.0), U256::from_be_bytes(value.0))
                    })
                    .collect(),
            )?;
        }
        (None, Some(account_state_diff)) => {
            for (slot, value) in account_state_diff {
                db.insert_account_storage(
                    account,
                    U256::from_be_bytes(slot.0),
                    U256::from_be_bytes(value.0),
                )?;
            }
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives::constants::GWEI_TO_WEI;

    #[test]
    fn test_ensure_0_fallback() {
        let CallFees { gas_price, .. } =
            CallFees::ensure_fees(None, None, None, U256::from(99), None, None, Some(U256::ZERO))
                .unwrap();
        assert!(gas_price.is_zero());
    }

    #[test]
    fn test_blob_fees() {
        let CallFees { gas_price, max_fee_per_blob_gas, .. } =
            CallFees::ensure_fees(None, None, None, U256::from(99), None, None, Some(U256::ZERO))
                .unwrap();
        assert!(gas_price.is_zero());
        assert_eq!(max_fee_per_blob_gas, None);

        let CallFees { gas_price, max_fee_per_blob_gas, .. } = CallFees::ensure_fees(
            None,
            None,
            None,
            U256::from(99),
            Some(&[B256::from(U256::ZERO)]),
            None,
            Some(U256::from(99)),
        )
        .unwrap();
        assert!(gas_price.is_zero());
        assert_eq!(max_fee_per_blob_gas, Some(U256::from(99)));
    }

    #[test]
    fn test_eip_1559_fees() {
        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(25 * GWEI_TO_WEI)),
            Some(U256::from(15 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(25 * GWEI_TO_WEI));

        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(25 * GWEI_TO_WEI)),
            Some(U256::from(5 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(20 * GWEI_TO_WEI));

        let CallFees { gas_price, .. } = CallFees::ensure_fees(
            None,
            Some(U256::from(30 * GWEI_TO_WEI)),
            Some(U256::from(30 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        )
        .unwrap();
        assert_eq!(gas_price, U256::from(30 * GWEI_TO_WEI));

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::from(30 * GWEI_TO_WEI)),
            Some(U256::from(31 * GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::from(5 * GWEI_TO_WEI)),
            Some(U256::from(GWEI_TO_WEI)),
            U256::from(15 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());

        let call_fees = CallFees::ensure_fees(
            None,
            Some(U256::MAX),
            Some(U256::MAX),
            U256::from(5 * GWEI_TO_WEI),
            None,
            None,
            Some(U256::ZERO),
        );
        assert!(call_fees.is_err());
    }
}
