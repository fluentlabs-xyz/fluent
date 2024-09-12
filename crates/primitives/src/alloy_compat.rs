//! Common conversions from alloy types.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use alloy_primitives::TxKind;
use alloy_rlp::Error as RlpError;
use revm_primitives::{hex, Bytes};

use crate::{
    constants::EMPTY_TRANSACTIONS,
    transaction::{extract_chain_id, ExecutionEnvironment},
    Block, Signature, Transaction, TransactionSigned, TransactionSignedEcRecovered, TxEip1559,
    TxEip2930, TxEip4844, TxLegacy, TxType,
};

impl TryFrom<alloy_rpc_types::Block> for Block {
    type Error = alloy_rpc_types::ConversionError;

    fn try_from(block: alloy_rpc_types::Block) -> Result<Self, Self::Error> {
        use alloy_rpc_types::ConversionError;

        let body = {
            let transactions: Result<Vec<TransactionSigned>, ConversionError> = match block
                .transactions
            {
                alloy_rpc_types::BlockTransactions::Full(transactions) => transactions
                    .into_iter()
                    .map(|tx| {
                        let signature = tx.signature.ok_or(ConversionError::MissingSignature)?;
                        Ok(TransactionSigned::from_transaction_and_signature(
                            tx.try_into()?,
                            crate::Signature {
                                r: signature.r,
                                s: signature.s,
                                odd_y_parity: signature
                                    .y_parity
                                    .unwrap_or_else(|| alloy_rpc_types::Parity(!signature.v.bit(0)))
                                    .0,
                            },
                        ))
                    })
                    .collect(),
                alloy_rpc_types::BlockTransactions::Hashes(_) |
                alloy_rpc_types::BlockTransactions::Uncle => {
                    // alloy deserializes empty blocks into `BlockTransactions::Hashes`, if the tx
                    // root is the empty root then we can just return an empty vec.
                    if block.header.transactions_root == EMPTY_TRANSACTIONS {
                        Ok(vec![])
                    } else {
                        Err(ConversionError::MissingFullTransactions)
                    }
                }
            };
            transactions?
        };

        Ok(Self {
            header: block.header.try_into()?,
            body,
            ommers: Default::default(),
            withdrawals: block.withdrawals.map(Into::into),
            // todo(onbjerg): we don't know if this is added to rpc yet, so for now we leave it as
            // empty.
            requests: None,
        })
    }
}

impl TryFrom<alloy_rpc_types::Transaction> for Transaction {
    type Error = alloy_rpc_types::ConversionError;

    fn try_from(tx: alloy_rpc_types::Transaction) -> Result<Self, Self::Error> {
        use alloy_eips::eip2718::Eip2718Error;
        use alloy_rpc_types::ConversionError;

        let tx_type = tx.transaction_type.map(TryInto::try_into).transpose();
        match tx_type.map_err(|_| {
            ConversionError::Eip2718Error(Eip2718Error::UnexpectedType(
                tx.transaction_type.unwrap(),
            ))
        })? {
            None | Some(TxType::Legacy) => {
                // legacy
                if tx.max_fee_per_gas.is_some() || tx.max_priority_fee_per_gas.is_some() {
                    return Err(ConversionError::Eip2718Error(
                        RlpError::Custom("EIP-1559 fields are present in a legacy transaction")
                            .into(),
                    ))
                }

                // extract the chain id if possible
                let chain_id = match tx.chain_id {
                    Some(chain_id) => Some(chain_id),
                    None => {
                        if let Some(signature) = tx.signature {
                            // TODO: make this error conversion better. This is needed because
                            // sometimes rpc providers return legacy transactions without a chain id
                            // explicitly in the response, however those transactions may also have
                            // a chain id in the signature from eip155
                            extract_chain_id(signature.v.to())
                                .map_err(|err| ConversionError::Eip2718Error(err.into()))?
                                .1
                        } else {
                            return Err(ConversionError::MissingChainId)
                        }
                    }
                };

                Ok(Self::Legacy(TxLegacy {
                    chain_id,
                    nonce: tx.nonce,
                    gas_price: tx.gas_price.ok_or(ConversionError::MissingGasPrice)?,
                    gas_limit: tx
                        .gas
                        .try_into()
                        .map_err(|_| ConversionError::Eip2718Error(RlpError::Overflow.into()))?,
                    to: tx.to.map_or(TxKind::Create, TxKind::Call),
                    value: tx.value,
                    input: tx.input,
                }))
            }
            Some(TxType::Eip2930) => {
                // eip2930
                Ok(Self::Eip2930(TxEip2930 {
                    chain_id: tx.chain_id.ok_or(ConversionError::MissingChainId)?,
                    nonce: tx.nonce,
                    gas_limit: tx
                        .gas
                        .try_into()
                        .map_err(|_| ConversionError::Eip2718Error(RlpError::Overflow.into()))?,
                    to: tx.to.map_or(TxKind::Create, TxKind::Call),
                    value: tx.value,
                    input: tx.input,
                    access_list: tx.access_list.ok_or(ConversionError::MissingAccessList)?,
                    gas_price: tx.gas_price.ok_or(ConversionError::MissingGasPrice)?,
                }))
            }
            Some(TxType::Eip1559) => {
                // EIP-1559
                Ok(Self::Eip1559(TxEip1559 {
                    chain_id: tx.chain_id.ok_or(ConversionError::MissingChainId)?,
                    nonce: tx.nonce,
                    max_priority_fee_per_gas: tx
                        .max_priority_fee_per_gas
                        .ok_or(ConversionError::MissingMaxPriorityFeePerGas)?,
                    max_fee_per_gas: tx
                        .max_fee_per_gas
                        .ok_or(ConversionError::MissingMaxFeePerGas)?,
                    gas_limit: tx
                        .gas
                        .try_into()
                        .map_err(|_| ConversionError::Eip2718Error(RlpError::Overflow.into()))?,
                    to: tx.to.map_or(TxKind::Create, TxKind::Call),
                    value: tx.value,
                    access_list: tx.access_list.ok_or(ConversionError::MissingAccessList)?,
                    input: tx.input,
                }))
            }
            Some(TxType::Eip4844) => {
                // EIP-4844
                Ok(Self::Eip4844(TxEip4844 {
                    chain_id: tx.chain_id.ok_or(ConversionError::MissingChainId)?,
                    nonce: tx.nonce,
                    max_priority_fee_per_gas: tx
                        .max_priority_fee_per_gas
                        .ok_or(ConversionError::MissingMaxPriorityFeePerGas)?,
                    max_fee_per_gas: tx
                        .max_fee_per_gas
                        .ok_or(ConversionError::MissingMaxFeePerGas)?,
                    gas_limit: tx
                        .gas
                        .try_into()
                        .map_err(|_| ConversionError::Eip2718Error(RlpError::Overflow.into()))?,
                    placeholder: tx.to.map(|_| ()),
                    to: tx.to.unwrap_or_default(),
                    value: tx.value,
                    access_list: tx.access_list.ok_or(ConversionError::MissingAccessList)?,
                    input: tx.input,
                    blob_versioned_hashes: tx
                        .blob_versioned_hashes
                        .ok_or(ConversionError::MissingBlobVersionedHashes)?,
                    max_fee_per_blob_gas: tx
                        .max_fee_per_blob_gas
                        .ok_or(ConversionError::MissingMaxFeePerBlobGas)?,
                }))
            }
            #[cfg(feature = "optimism")]
            Some(TxType::Deposit) => Ok(Self::Deposit(crate::transaction::TxDeposit {
                source_hash: tx
                    .other
                    .get_deserialized::<String>("sourceHash")
                    .ok_or_else(|| ConversionError::Custom("MissingSourceHash".to_string()))?
                    .map_err(|_| ConversionError::Custom("MissingSourceHash".to_string()))?
                    .parse()
                    .map_err(|_| ConversionError::Custom("InvalidSourceHash".to_string()))?,
                from: tx.from,
                to: TxKind::from(tx.to),
                mint: Option::transpose(
                    tx.other.get_deserialized::<alloy_primitives::U128>("mint"),
                )
                .map_err(|_| ConversionError::Custom("MissingMintValue".to_string()))?
                .map(|num| num.to::<u128>())
                .filter(|num| *num > 0),
                value: tx.value,
                gas_limit: tx
                    .gas
                    .try_into()
                    .map_err(|_| ConversionError::Eip2718Error(RlpError::Overflow.into()))?,
                is_system_transaction: tx.from == crate::constants::OP_SYSTEM_TX_FROM_ADDR,
                input: tx.input,
            })),
            Some(TxType::FluentV1) => {
                let execution_environment_type = tx
                    .other
                    .get_deserialized::<String>("executionEnvironment")
                    .ok_or_else(|| {
                        ConversionError::Custom("MissingExecutionEnvironment".to_string())
                    })?
                    .map_err(|_| {
                        ConversionError::Custom("InvalidExecutionEnvironment".to_string())
                    })?;
                let raw_data = tx
                    .other
                    .get_deserialized::<String>("rawData")
                    .ok_or_else(|| ConversionError::Custom("MissingRawData".to_string()))?
                    .map_err(|_| ConversionError::Custom("InvalidRawData".to_string()))?;

                let raw_data = raw_data.trim_start_matches("0x");
                let raw_data = hex::decode(raw_data)
                    .map_err(|_| ConversionError::Custom("InvalidRawData".to_string()))?;
                let raw_data = Bytes::from(raw_data);

                let execution_environment = ExecutionEnvironment::from_str_with_data(
                    &execution_environment_type,
                    raw_data.clone().into(),
                )
                .map_err(|_| ConversionError::Custom("InvalidExecutionEnvironment".to_string()))?;

                Ok(Self::FluentV1(crate::transaction::TxFluentV1 {
                    execution_environment,
                    data: raw_data.into(),
                }))
            }
        }
    }
}

impl TryFrom<alloy_rpc_types::Transaction> for TransactionSigned {
    type Error = alloy_rpc_types::ConversionError;

    fn try_from(tx: alloy_rpc_types::Transaction) -> Result<Self, Self::Error> {
        use alloy_rpc_types::ConversionError;

        let signature = tx.signature.ok_or(ConversionError::MissingSignature)?;
        let transaction: Transaction = tx.try_into()?;

        Ok(Self::from_transaction_and_signature(
            transaction.clone(),
            Signature {
                r: signature.r,
                s: signature.s,
                odd_y_parity: if let Some(y_parity) = signature.y_parity {
                    y_parity.0
                } else {
                    match transaction.tx_type() {
                        // If the transaction type is Legacy, adjust the v component of the
                        // signature according to the Ethereum specification
                        TxType::Legacy => {
                            extract_chain_id(signature.v.to())
                                .map_err(|_| ConversionError::InvalidSignature)?
                                .0
                        }
                        _ => !signature.v.is_zero(),
                    }
                },
            },
        ))
    }
}

impl TryFrom<alloy_rpc_types::Transaction> for TransactionSignedEcRecovered {
    type Error = alloy_rpc_types::ConversionError;

    fn try_from(tx: alloy_rpc_types::Transaction) -> Result<Self, Self::Error> {
        use alloy_rpc_types::ConversionError;

        let transaction: TransactionSigned = tx.try_into()?;

        transaction.try_into_ecrecovered().map_err(|_| ConversionError::InvalidSignature)
    }
}

impl TryFrom<alloy_rpc_types::Signature> for Signature {
    type Error = alloy_rpc_types::ConversionError;

    fn try_from(signature: alloy_rpc_types::Signature) -> Result<Self, Self::Error> {
        use alloy_rpc_types::ConversionError;

        let odd_y_parity = if let Some(y_parity) = signature.y_parity {
            y_parity.0
        } else {
            extract_chain_id(signature.v.to()).map_err(|_| ConversionError::InvalidSignature)?.0
        };

        Ok(Self { r: signature.r, s: signature.s, odd_y_parity })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxFluentV1;
    use alloy_rpc_types::Transaction as AlloyTransaction;
    use assert_matches::assert_matches;
    use core::str::FromStr;
    use fluentbase_core::fvm::helpers::FUEL_TESTNET_BASE_ASSET_ID;
    use fluentbase_types::DEVNET_CHAIN_ID;
    use fuel_core_types::{
        fuel_asm::{op, RegId},
        fuel_crypto::coins_bip32::ecdsa::signature::rand_core::SeedableRng,
        fuel_types::{canonical::Serialize, BlockHeight},
    };
    use fuel_tx::{
        ConsensusParameters, Input, Output, TransactionBuilder, TxId, TxPointer, UniqueIdentifier,
        UtxoId,
    };
    use fuel_vm::{
        fuel_crypto::SecretKey,
        fuel_types::{AssetId, ChainId},
        storage::MemoryStorage,
    };
    use rand::rngs::StdRng;
    use revm_primitives::Bytes;

    #[test]
    fn fluent_v1_tx_conversion() {
        // type - represents the Fluent transaction type
        // executionEnvironment - represents the execution environment of the transaction (e.g.
        // Solana, Fuel) rawData - represents the raw data of the transaction
        // other fields can be filled with zeros
        let input = r#"{
            "chainId": "0x1",
            "type": "0x52",
            "executionEnvironment": "0x01",
            "rawData": "0x0bf1845c5d7a82ec92365d5027f7310793d53004f3c86aa80965c67bf7e7dc80",
            "from": "0x0000000000000000000000000000000000000000",
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "gas": "0x0",
            "gasPrice": "0x0",
            "input": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0",
            "value": "0x0"
        }"#;
        let alloy_tx: AlloyTransaction =
            serde_json::from_str(input).expect("failed to deserialize");

        let reth_tx: Transaction = alloy_tx.try_into().expect("alloy tx convertable to reth tx");
        match reth_tx {
            Transaction::FluentV1(fluent_tx) => {
                assert_eq!(fluent_tx.tx_type(), TxType::FluentV1);

                assert_matches!(
                    fluent_tx.execution_environment,
                    ExecutionEnvironment::Solana(..),
                    "solana EE expected"
                );
            }
            _ => panic!("Expected FluentV1 transaction, but got a different type"),
        }
    }

    #[test]
    fn fluent_v1_tx_conversion_with_fuel_tx_ee() {
        let mut tb = fuel_vm::util::test_helpers::TestBuilder::new(1234u64);
        tb.with_chain_id(ChainId::new(DEVNET_CHAIN_ID));
        let tx1 = tb
            .coin_input(AssetId::default(), 100)
            .change_output(AssetId::default())
            .build()
            .transaction()
            .clone();
        let tx1: fuel_tx::Transaction = fuel_tx::Transaction::Script(tx1);
        let tx_raw_data = tx1.to_bytes();
        let tx1_id = tx1.id(&tb.get_chain_id());
        println!("tx1_id {}", hex::encode(&tx1_id));
        let tx_raw_data_hex = hex::encode(&tx_raw_data);
        let input = r#"{
            "chainId": "1337",
            "type": "0x52",
            "executionEnvironment": "0x00",
            "rawData": "0x#RAW_DATA#",
            "from": "0x0000000000000000000000000000000000000000",
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "gas": "0x0",
            "gasPrice": "0x0",
            "input": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0",
            "value": "0x0"
        }"#
        .replace("#RAW_DATA#", tx_raw_data_hex.as_str());
        println!("tx_raw_data_hex {}", &tx_raw_data_hex);
        let alloy_tx: AlloyTransaction =
            serde_json::from_str(input.as_str()).expect("input is a valid alloy tx");

        let reth_tx: Transaction = alloy_tx.try_into().expect("alloy tx convertable to reth tx");
        match reth_tx {
            Transaction::FluentV1(fluent_tx) => {
                assert_eq!(fluent_tx.tx_type(), TxType::FluentV1);

                assert_matches!(
                    fluent_tx.execution_environment,
                    ExecutionEnvironment::Fuel(..),
                    "Fuel EE expected"
                );
            }
            _ => panic!("Expected FluentV1 transaction, but got a different type"),
        }
    }

    #[test]
    fn encode_decode_transaction_signed_script_fluent() {
        let mut tb = fuel_vm::util::test_helpers::TestBuilder::new(1234u64);
        let chain_id = DEVNET_CHAIN_ID;
        tb.with_chain_id(ChainId::new(chain_id));
        let tx1 = tb
            .coin_input(AssetId::default(), 100)
            .change_output(AssetId::default())
            .build()
            .transaction()
            .clone();
        let tx1: fuel_tx::Transaction = fuel_tx::Transaction::Script(tx1);
        let mut tx_raw_data_vec = vec![];
        tx_raw_data_vec.extend_from_slice(tx1.to_bytes().as_slice());
        let tx_raw_data_bytes = Bytes::from(tx_raw_data_vec);
        println!("tx_raw hex: {}", hex::encode(&tx_raw_data_bytes));

        let fuel_ee = ExecutionEnvironment::new(0, tx_raw_data_bytes.clone()).unwrap();

        let transaction_signed = TransactionSigned {
            hash: Default::default(),
            signature: Default::default(),
            transaction: Transaction::FluentV1(TxFluentV1::new(fuel_ee, tx_raw_data_bytes)),
        };

        let local_transactions = vec![transaction_signed];

        let mut buf = vec![];

        alloy_rlp::encode_list(&local_transactions, &mut buf);

        let txs: Vec<TransactionSigned> =
            alloy_rlp::Decodable::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn encode_decode_transaction_signed_script_simple_transfer_fluent() {
        let bytecode = core::iter::once(op::ret(RegId::ZERO)).collect();
        let mut test_builder = fuel_vm::util::test_helpers::TestBuilder {
            rng: StdRng::seed_from_u64(1234),
            gas_price: 0,
            max_fee_limit: 0,
            script_gas_limit: 100,
            builder: TransactionBuilder::script(bytecode, vec![]),
            storage: MemoryStorage::default(),
            block_height: Default::default(),
            consensus_params: ConsensusParameters::standard(),
        };

        let base_asset_id = AssetId::from_str(FUEL_TESTNET_BASE_ASSET_ID).unwrap();

        let secret1 = "0x99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61";
        let secret1_vec = hex::decode(secret1).unwrap();
        let secret1_secret_key = SecretKey::try_from(secret1_vec.as_slice()).unwrap();
        let secret1_address = Input::owner(&secret1_secret_key.public_key());
        println!("secret1_address: {}", secret1_address);

        let secret2 = "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";
        let secret2_vec = hex::decode(secret2).unwrap();
        let secret2_secret_key = SecretKey::try_from(secret2_vec.as_slice()).unwrap();
        let secret2_address = Input::owner(&secret2_secret_key.public_key());
        println!("secret2_address: {}", secret2_address);

        let chain_id = DEVNET_CHAIN_ID;
        test_builder.with_chain_id(ChainId::new(chain_id));
        let tx_id: TxId =
            TxId::from_str("0x0000000000000000000000000000000000000000000000000000000000001000")
                .unwrap();
        let utxo_id = UtxoId::new(tx_id, 0);
        test_builder.builder.add_unsigned_coin_input(
            secret1_secret_key.clone(),
            utxo_id,
            0xffff,
            base_asset_id,
            TxPointer::new(BlockHeight::new(0), 0),
        );
        test_builder.builder.add_output(Output::change(secret1_address.clone(), 0, base_asset_id));
        test_builder.builder.add_output(Output::coin(secret2_address.clone(), 1, base_asset_id));
        let tx1 = test_builder.build().transaction().clone();
        let tx1: fuel_tx::Transaction = fuel_tx::Transaction::Script(tx1);
        let mut tx_raw_data_vec = vec![];
        tx_raw_data_vec.extend_from_slice(tx1.to_bytes().as_slice());
        let tx_raw_data_bytes = Bytes::from(tx_raw_data_vec);
        println!("tx_raw hex: {}", hex::encode(&tx_raw_data_bytes));

        let fuel_ee = ExecutionEnvironment::new(0, tx_raw_data_bytes.clone()).unwrap();

        let transaction_signed = TransactionSigned {
            hash: Default::default(),
            signature: Default::default(),
            transaction: Transaction::FluentV1(TxFluentV1::new(fuel_ee, tx_raw_data_bytes)),
        };

        let local_transactions = vec![transaction_signed];

        let mut buf = vec![];

        alloy_rlp::encode_list(&local_transactions, &mut buf);

        let txs: Vec<TransactionSigned> =
            alloy_rlp::Decodable::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(txs.len(), 1);
    }

    #[test]
    #[cfg(feature = "optimism")]
    fn optimism_deposit_tx_conversion_no_mint() {
        let input = r#"{
            "blockHash": "0xef664d656f841b5ad6a2b527b963f1eb48b97d7889d742f6cbff6950388e24cd",
            "blockNumber": "0x73a78fd",
            "depositReceiptVersion": "0x1",
            "from": "0x36bde71c97b33cc4729cf772ae268934f7ab70b2",
            "gas": "0xc27a8",
            "gasPrice": "0x0",
            "hash": "0x0bf1845c5d7a82ec92365d5027f7310793d53004f3c86aa80965c67bf7e7dc80",
            "input": "0xd764ad0b000100000000000000000000000000000000000000000000000000000001cf5400000000000000000000000099c9fc46f92e8a1c0dec1b1747d010903e884be100000000000000000000000042000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a12000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e40166a07a0000000000000000000000000994206dfe8de6ec6920ff4d779b0d950605fb53000000000000000000000000d533a949740bb3306d119cc777fa900ba034cd52000000000000000000000000ca74f404e0c7bfa35b13b511097df966d5a65597000000000000000000000000ca74f404e0c7bfa35b13b511097df966d5a65597000000000000000000000000000000000000000000000216614199391dbba2ba00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "mint": "0x0",
            "nonce": "0x74060",
            "r": "0x0",
            "s": "0x0",
            "sourceHash": "0x074adb22f2e6ed9bdd31c52eefc1f050e5db56eb85056450bccd79a6649520b3",
            "to": "0x4200000000000000000000000000000000000007",
            "transactionIndex": "0x1",
            "type": "0x7e",
            "v": "0x0",
            "value": "0x0"
        }"#;
        let alloy_tx: AlloyTransaction =
            serde_json::from_str(input).expect("failed to deserialize");

        let reth_tx: Transaction = alloy_tx.try_into().expect("failed to convert");
        if let Transaction::Deposit(deposit_tx) = reth_tx {
            assert_eq!(
                deposit_tx.source_hash,
                "0x074adb22f2e6ed9bdd31c52eefc1f050e5db56eb85056450bccd79a6649520b3"
                    .parse::<B256>()
                    .unwrap()
            );
            assert_eq!(
                deposit_tx.from,
                "0x36bde71c97b33cc4729cf772ae268934f7ab70b2".parse::<Address>().unwrap()
            );
            assert_eq!(
                deposit_tx.to,
                TxKind::from(address!("4200000000000000000000000000000000000007"))
            );
            assert_eq!(deposit_tx.mint, None);
            assert_eq!(deposit_tx.value, U256::ZERO);
            assert_eq!(deposit_tx.gas_limit, 796584);
            assert!(!deposit_tx.is_system_transaction);
        } else {
            panic!("Expected Deposit transaction");
        }
    }

    #[test]
    #[cfg(feature = "optimism")]
    fn optimism_deposit_tx_conversion_mint() {
        let input = r#"{
            "blockHash": "0x7194f63b105e93fb1a27c50d23d62e422d4185a68536c55c96284911415699b2",
            "blockNumber": "0x73a82cc",
            "depositReceiptVersion": "0x1",
            "from": "0x36bde71c97b33cc4729cf772ae268934f7ab70b2",
            "gas": "0x7812e",
            "gasPrice": "0x0",
            "hash": "0xf7e83886d3c6864f78e01c453ebcd57020c5795d96089e8f0e0b90a467246ddb",
            "input": "0xd764ad0b000100000000000000000000000000000000000000000000000000000001cf5f00000000000000000000000099c9fc46f92e8a1c0dec1b1747d010903e884be100000000000000000000000042000000000000000000000000000000000000100000000000000000000000000000000000000000000000239c2e16a5ca5900000000000000000000000000000000000000000000000000000000000000030d4000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e41635f5fd0000000000000000000000002ce910fbba65b454bbaf6a18c952a70f3bcd82990000000000000000000000002ce910fbba65b454bbaf6a18c952a70f3bcd82990000000000000000000000000000000000000000000000239c2e16a5ca590000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "mint": "0x239c2e16a5ca590000",
            "nonce": "0x7406b",
            "r": "0x0",
            "s": "0x0",
            "sourceHash": "0xe0358cd2b2686d297c5c859646a613124a874fb9d9c4a2c88636a46a65c06e48",
            "to": "0x4200000000000000000000000000000000000007",
            "transactionIndex": "0x1",
            "type": "0x7e",
            "v": "0x0",
            "value": "0x239c2e16a5ca590000"
        }"#;
        let alloy_tx: AlloyTransaction =
            serde_json::from_str(input).expect("failed to deserialize");

        let reth_tx: Transaction = alloy_tx.try_into().expect("failed to convert");

        if let Transaction::Deposit(deposit_tx) = reth_tx {
            assert_eq!(
                deposit_tx.source_hash,
                "0xe0358cd2b2686d297c5c859646a613124a874fb9d9c4a2c88636a46a65c06e48"
                    .parse::<B256>()
                    .unwrap()
            );
            assert_eq!(
                deposit_tx.from,
                "0x36bde71c97b33cc4729cf772ae268934f7ab70b2".parse::<Address>().unwrap()
            );
            assert_eq!(
                deposit_tx.to,
                TxKind::from(address!("4200000000000000000000000000000000000007"))
            );
            assert_eq!(deposit_tx.mint, Some(656890000000000000000));
            assert_eq!(deposit_tx.value, U256::from(0x239c2e16a5ca590000_u128));
            assert_eq!(deposit_tx.gas_limit, 491822);
            assert!(!deposit_tx.is_system_transaction);
        } else {
            panic!("Expected Deposit transaction");
        }
    }
}
