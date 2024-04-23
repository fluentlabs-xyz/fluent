//! Reth genesis initialization utility functions.

use fluentbase_genesis::devnet::POSEIDON_HASH_KEY;
use fluentbase_poseidon::poseidon_hash;
use reth_db::{
    database::Database,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_interfaces::{db::DatabaseError, provider::ProviderResult};
use reth_primitives::{
    stage::StageId, Account, Bytecode, ChainSpec, Receipts, StaticFileSegment, StorageEntry, B256,
    U256,
};
use reth_provider::{
    bundle_state::{BundleStateInit, RevertsInit},
    providers::{StaticFileProvider, StaticFileWriter},
    BlockHashReader, BundleStateWithReceipts, ChainSpecProvider, DatabaseProviderRW, HashingWriter,
    HistoryWriter, OriginalValuesKnown, ProviderError, ProviderFactory,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tracing::debug;

/// Database initialization error type.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum InitDatabaseError {
    /// An existing genesis block was found in the database, and its hash did not match the hash of
    /// the chainspec.
    #[error("genesis hash in the database does not match the specified chainspec: chainspec is {chainspec_hash}, database is {database_hash}")]
    GenesisHashMismatch {
        /// Expected genesis hash.
        chainspec_hash: B256,
        /// Actual genesis hash.
        database_hash: B256,
    },

    /// Provider error.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

impl From<DatabaseError> for InitDatabaseError {
    fn from(error: DatabaseError) -> Self {
        Self::Provider(ProviderError::Database(error))
    }
}

/// Write the genesis block if it has not already been written
pub fn init_genesis<DB: Database>(factory: ProviderFactory<DB>) -> Result<B256, InitDatabaseError> {
    let chain = factory.chain_spec();

    let genesis = chain.genesis();
    let hash = chain.genesis_hash();

    // Check if we already have the genesis header or if we have the wrong one.
    match factory.block_hash(0) {
        Ok(None) | Err(ProviderError::MissingStaticFileBlock(StaticFileSegment::Headers, 0)) => {}
        Ok(Some(block_hash)) => {
            if block_hash == hash {
                debug!("Genesis already written, skipping.");
                return Ok(hash);
            }

            return Err(InitDatabaseError::GenesisHashMismatch {
                chainspec_hash: hash,
                database_hash: block_hash,
            });
        }
        Err(e) => return Err(dbg!(e).into()),
    }

    debug!("Writing genesis block.");

    // use transaction to insert genesis header
    let provider_rw = factory.provider_rw()?;
    insert_genesis_hashes(&provider_rw, genesis)?;
    insert_genesis_history(&provider_rw, genesis)?;

    // Insert header
    let tx = provider_rw.into_tx();
    let static_file_provider = factory.static_file_provider();
    insert_genesis_header::<DB>(&tx, &static_file_provider, chain.clone())?;

    insert_genesis_state::<DB>(&tx, genesis)?;

    // insert sync stage
    for stage in StageId::ALL.iter() {
        tx.put::<tables::StageCheckpoints>(stage.to_string(), Default::default())?;
    }

    tx.commit()?;
    static_file_provider.commit()?;

    Ok(hash)
}

/// Inserts the genesis state into the database.
pub fn insert_genesis_state<DB: Database>(
    tx: &<DB as Database>::TXMut,
    genesis: &reth_primitives::Genesis,
) -> ProviderResult<()> {
    let capacity = genesis.alloc.len();
    let mut state_init: BundleStateInit = HashMap::with_capacity(capacity);
    let mut reverts_init = HashMap::with_capacity(capacity);
    let mut contracts: HashMap<B256, Bytecode> = HashMap::with_capacity(capacity);

    for (address, account) in &genesis.alloc {
        let bytecode_hash = if let Some(code) = &account.code {
            let bytecode = Bytecode::new_raw(code.clone());
            let hash = bytecode.hash_slow();
            let rwasm_hash = account
                .storage
                .as_ref()
                .and_then(|s| s.get(&POSEIDON_HASH_KEY))
                .cloned()
                .unwrap_or_else(|| poseidon_hash(bytecode.original_bytes().as_ref()).into());
            contracts.insert(hash, bytecode.clone());
            contracts.insert(rwasm_hash, bytecode);
            Some((hash, rwasm_hash))
        } else {
            None
        };

        // get state
        let storage = account
            .storage
            .as_ref()
            .map(|m| {
                m.iter()
                    .map(|(key, value)| {
                        let value = U256::from_be_bytes(value.0);
                        (*key, (U256::ZERO, value))
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        reverts_init.insert(
            *address,
            (Some(None), storage.keys().map(|k| StorageEntry::new(*k, U256::ZERO)).collect()),
        );

        state_init.insert(
            *address,
            (
                None,
                Some(Account {
                    nonce: account.nonce.unwrap_or_default(),
                    balance: account.balance,
                    bytecode_hash: bytecode_hash.map(|v| v.0),
                    rwasm_hash: bytecode_hash.map(|v| v.1),
                }),
                storage,
            ),
        );
    }
    let all_reverts_init: RevertsInit = HashMap::from([(0, reverts_init)]);

    let bundle = BundleStateWithReceipts::new_init(
        state_init,
        all_reverts_init,
        contracts.into_iter().collect(),
        Receipts::new(),
        0,
    );

    bundle.write_to_storage(tx, None, OriginalValuesKnown::Yes)?;

    Ok(())
}

/// Inserts hashes for the genesis state.
pub fn insert_genesis_hashes<DB: Database>(
    provider: &DatabaseProviderRW<DB>,
    genesis: &reth_primitives::Genesis,
) -> ProviderResult<()> {
    // insert and hash accounts to hashing table
    let alloc_accounts = genesis
        .alloc
        .clone()
        .into_iter()
        .map(|(addr, account)| (addr, Some(Account::from_genesis_account(account))));
    provider.insert_account_for_hashing(alloc_accounts)?;

    let alloc_storage = genesis.alloc.clone().into_iter().filter_map(|(addr, account)| {
        // only return Some if there is storage
        account.storage.map(|storage| {
            (
                addr,
                storage.into_iter().map(|(key, value)| StorageEntry { key, value: value.into() }),
            )
        })
    });
    provider.insert_storage_for_hashing(alloc_storage)?;

    Ok(())
}

/// Inserts history indices for genesis accounts and storage.
pub fn insert_genesis_history<DB: Database>(
    provider: &DatabaseProviderRW<DB>,
    genesis: &reth_primitives::Genesis,
) -> ProviderResult<()> {
    let account_transitions =
        genesis.alloc.keys().map(|addr| (*addr, vec![0])).collect::<BTreeMap<_, _>>();
    provider.insert_account_history_index(account_transitions)?;

    let storage_transitions = genesis
        .alloc
        .iter()
        .filter_map(|(addr, account)| account.storage.as_ref().map(|storage| (addr, storage)))
        .flat_map(|(addr, storage)| storage.iter().map(|(key, _)| ((*addr, *key), vec![0])))
        .collect::<BTreeMap<_, _>>();
    provider.insert_storage_history_index(storage_transitions)?;

    Ok(())
}

/// Inserts header for the genesis state.
pub fn insert_genesis_header<DB: Database>(
    tx: &<DB as Database>::TXMut,
    static_file_provider: &StaticFileProvider,
    chain: Arc<ChainSpec>,
) -> ProviderResult<()> {
    let (header, block_hash) = chain.sealed_genesis_header().split();

    match static_file_provider.block_hash(0) {
        Ok(None) | Err(ProviderError::MissingStaticFileBlock(StaticFileSegment::Headers, 0)) => {
            let (difficulty, hash) = (header.difficulty, block_hash);
            let mut writer = static_file_provider.latest_writer(StaticFileSegment::Headers)?;
            writer.append_header(header, difficulty, hash)?;
        }
        Ok(Some(_)) => {}
        Err(e) => return Err(e),
    }

    tx.put::<tables::HeaderNumbers>(block_hash, 0)?;
    tx.put::<tables::BlockBodyIndices>(0, Default::default())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use reth_db::{
        cursor::DbCursorRO,
        models::{storage_sharded_key::StorageShardedKey, ShardedKey},
        table::{Table, TableRow},
        DatabaseEnv,
    };
    use reth_primitives::{
        Address, Chain, ForkTimestamps, Genesis, GenesisAccount, IntegerList, GOERLI,
        GOERLI_GENESIS_HASH, MAINNET, MAINNET_GENESIS_HASH, SEPOLIA, SEPOLIA_GENESIS_HASH,
    };
    use reth_provider::test_utils::create_test_provider_factory_with_chain_spec;

    fn collect_table_entries<DB, T>(
        tx: &<DB as Database>::TX,
    ) -> Result<Vec<TableRow<T>>, InitDatabaseError>
    where
        DB: Database,
        T: Table,
    {
        Ok(tx.cursor_read::<T>()?.walk_range(..)?.collect::<Result<Vec<_>, _>>()?)
    }

    #[test]
    fn success_init_genesis_mainnet() {
        let genesis_hash =
            init_genesis(create_test_provider_factory_with_chain_spec(MAINNET.clone())).unwrap();

        // actual, expected
        assert_eq!(genesis_hash, MAINNET_GENESIS_HASH);
    }

    #[test]
    fn success_init_genesis_goerli() {
        let genesis_hash =
            init_genesis(create_test_provider_factory_with_chain_spec(GOERLI.clone())).unwrap();

        // actual, expected
        assert_eq!(genesis_hash, GOERLI_GENESIS_HASH);
    }

    #[test]
    fn success_init_genesis_sepolia() {
        let genesis_hash =
            init_genesis(create_test_provider_factory_with_chain_spec(SEPOLIA.clone())).unwrap();

        // actual, expected
        assert_eq!(genesis_hash, SEPOLIA_GENESIS_HASH);
    }

    #[test]
    fn fail_init_inconsistent_db() {
        let factory = create_test_provider_factory_with_chain_spec(SEPOLIA.clone());
        let static_file_provider = factory.static_file_provider();
        init_genesis(factory.clone()).unwrap();

        // Try to init db with a different genesis block
        let genesis_hash = init_genesis(
            ProviderFactory::new(
                factory.into_db(),
                MAINNET.clone(),
                static_file_provider.path().into(),
            )
            .unwrap(),
        );

        assert_eq!(
            genesis_hash.unwrap_err(),
            InitDatabaseError::GenesisHashMismatch {
                chainspec_hash: MAINNET_GENESIS_HASH,
                database_hash: SEPOLIA_GENESIS_HASH
            }
        )
    }

    #[test]
    fn init_genesis_history() {
        let address_with_balance = Address::with_last_byte(1);
        let address_with_storage = Address::with_last_byte(2);
        let storage_key = B256::with_last_byte(1);
        let chain_spec = Arc::new(ChainSpec {
            chain: Chain::from_id(1),
            genesis: Genesis {
                alloc: BTreeMap::from([
                    (
                        address_with_balance,
                        GenesisAccount { balance: U256::from(1), ..Default::default() },
                    ),
                    (
                        address_with_storage,
                        GenesisAccount {
                            storage: Some(BTreeMap::from([(storage_key, B256::random())])),
                            ..Default::default()
                        },
                    ),
                ]),
                ..Default::default()
            },
            hardforks: BTreeMap::default(),
            fork_timestamps: ForkTimestamps::default(),
            genesis_hash: None,
            paris_block_and_final_difficulty: None,
            deposit_contract: None,
            ..Default::default()
        });

        let factory = create_test_provider_factory_with_chain_spec(chain_spec);
        init_genesis(factory.clone()).unwrap();

        let provider = factory.provider().unwrap();

        let tx = provider.tx_ref();

        assert_eq!(
            collect_table_entries::<Arc<DatabaseEnv>, tables::AccountsHistory>(tx)
                .expect("failed to collect"),
            vec![
                (ShardedKey::new(address_with_balance, u64::MAX), IntegerList::new([0]).unwrap()),
                (ShardedKey::new(address_with_storage, u64::MAX), IntegerList::new([0]).unwrap())
            ],
        );

        assert_eq!(
            collect_table_entries::<Arc<DatabaseEnv>, tables::StoragesHistory>(tx)
                .expect("failed to collect"),
            vec![(
                StorageShardedKey::new(address_with_storage, storage_key, u64::MAX),
                IntegerList::new([0]).unwrap()
            )],
        );
    }
}
