//! Command for debugging in-memory merkle trie calculation.

use crate::{
    args::{
        get_secret_key,
        utils::{chain_help, genesis_value_parser, SUPPORTED_CHAINS},
        DatabaseArgs, NetworkArgs,
    },
    core::cli::runner::CliContext,
    dirs::{DataDirPath, MaybePlatformPath},
    utils::{get_single_body, get_single_header},
};
use backon::{ConstantBuilder, Retryable};
use clap::Parser;
use reth_config::Config;
use reth_db::{init_db, DatabaseEnv};
use reth_interfaces::executor::BlockValidationError;
use reth_network::NetworkHandle;
use reth_network_api::NetworkInfo;
use reth_node_ethereum::EthEvmConfig;
use reth_primitives::{fs, stage::StageId, BlockHashOrNumber, ChainSpec};
use reth_provider::{
    AccountExtReader, ExecutorFactory, HashingWriter, HeaderProvider, LatestStateProviderRef,
    OriginalValuesKnown, ProviderFactory, StageCheckpointReader, StorageReader,
};
use reth_tasks::TaskExecutor;
use reth_trie::{updates::TrieKey, StateRoot};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::*;

/// `reth debug in-memory-merkle` command
/// This debug routine requires that the node is positioned at the block before the target.
/// The script will then download the block from p2p network and attempt to calculate and verify
/// merkle root for it.
#[derive(Debug, Parser)]
pub struct Command {
    /// The path to the data dir for all reth files and subdirectories.
    ///
    /// Defaults to the OS-specific data directory:
    ///
    /// - Linux: `$XDG_DATA_HOME/reth/` or `$HOME/.local/share/reth/`
    /// - Windows: `{FOLDERID_RoamingAppData}/reth/`
    /// - macOS: `$HOME/Library/Application Support/reth/`
    #[arg(long, value_name = "DATA_DIR", verbatim_doc_comment, default_value_t)]
    datadir: MaybePlatformPath<DataDirPath>,

    /// The chain this node is running.
    ///
    /// Possible values are either a built-in chain or the path to a chain specification file.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        long_help = chain_help(),
        default_value = SUPPORTED_CHAINS[0],
        value_parser = genesis_value_parser
    )]
    chain: Arc<ChainSpec>,

    #[command(flatten)]
    db: DatabaseArgs,

    #[command(flatten)]
    network: NetworkArgs,

    /// The number of retries per request
    #[arg(long, default_value = "5")]
    retries: usize,

    /// The depth after which we should start comparing branch nodes
    #[arg(long)]
    skip_node_depth: Option<usize>,
}

impl Command {
    async fn build_network(
        &self,
        config: &Config,
        task_executor: TaskExecutor,
        db: Arc<DatabaseEnv>,
        network_secret_path: PathBuf,
        default_peers_path: PathBuf,
    ) -> eyre::Result<NetworkHandle> {
        let secret_key = get_secret_key(&network_secret_path)?;
        let network = self
            .network
            .network_config(config, self.chain.clone(), secret_key, default_peers_path)
            .with_task_executor(Box::new(task_executor))
            .listener_addr(SocketAddr::new(self.network.addr, self.network.port))
            .discovery_addr(SocketAddr::new(
                self.network.discovery.addr,
                self.network.discovery.port,
            ))
            .build(ProviderFactory::new(
                db,
                self.chain.clone(),
                self.datadir.unwrap_or_chain_default(self.chain.chain).static_files_path(),
            )?)
            .start_network()
            .await?;
        info!(target: "reth::cli", peer_id = %network.peer_id(), local_addr = %network.local_addr(), "Connected to P2P network");
        debug!(target: "reth::cli", peer_id = ?network.peer_id(), "Full peer ID");
        Ok(network)
    }

    /// Execute `debug in-memory-merkle` command
    pub async fn execute(self, ctx: CliContext) -> eyre::Result<()> {
        let config = Config::default();

        // add network name to data dir
        let data_dir = self.datadir.unwrap_or_chain_default(self.chain.chain);
        let db_path = data_dir.db_path();
        fs::create_dir_all(&db_path)?;

        // initialize the database
        let db = Arc::new(init_db(db_path, self.db.database_args())?);
        let factory = ProviderFactory::new(&db, self.chain.clone(), data_dir.static_files_path())?;
        let provider = factory.provider()?;

        // Look up merkle checkpoint
        let merkle_checkpoint = provider
            .get_stage_checkpoint(StageId::MerkleExecute)?
            .expect("merkle checkpoint exists");

        let merkle_block_number = merkle_checkpoint.block_number;

        // Configure and build network
        let network_secret_path =
            self.network.p2p_secret_key.clone().unwrap_or_else(|| data_dir.p2p_secret_path());
        let network = self
            .build_network(
                &config,
                ctx.task_executor.clone(),
                db.clone(),
                network_secret_path,
                data_dir.known_peers_path(),
            )
            .await?;

        let target_block_number = merkle_block_number + 1;

        info!(target: "reth::cli", target_block_number, "Downloading full block");
        let fetch_client = network.fetch_client().await?;

        let retries = self.retries.max(1);
        let backoff = ConstantBuilder::default().with_max_times(retries);

        let client = fetch_client.clone();
        let header = (move || {
            get_single_header(client.clone(), BlockHashOrNumber::Number(target_block_number))
        })
        .retry(&backoff)
        .notify(|err, _| warn!(target: "reth::cli", "Error requesting header: {err}. Retrying..."))
        .await?;

        let client = fetch_client.clone();
        let chain = Arc::clone(&self.chain);
        let block = (move || get_single_body(client.clone(), Arc::clone(&chain), header.clone()))
            .retry(&backoff)
            .notify(
                |err, _| warn!(target: "reth::cli", "Error requesting body: {err}. Retrying..."),
            )
            .await?;

        let executor_factory =
            reth_revm::EvmProcessorFactory::new(self.chain.clone(), EthEvmConfig::default());
        let mut executor = executor_factory.with_state(LatestStateProviderRef::new(
            provider.tx_ref(),
            factory.static_file_provider(),
        ));

        let merkle_block_td =
            provider.header_td_by_number(merkle_block_number)?.unwrap_or_default();
        executor.execute_and_verify_receipt(
            &block
                .clone()
                .unseal()
                .with_recovered_senders()
                .ok_or(BlockValidationError::SenderRecoveryError)?,
            merkle_block_td + block.difficulty,
        )?;
        let block_state = executor.take_output_state();

        // Unpacked `BundleState::state_root_slow` function
        let (in_memory_state_root, in_memory_updates) =
            block_state.hash_state_slow().state_root_with_updates(provider.tx_ref())?;

        if in_memory_state_root == block.state_root {
            info!(target: "reth::cli", state_root = ?in_memory_state_root, "Computed in-memory state root matches");
            return Ok(());
        }

        let provider_rw = factory.provider_rw()?;

        // Insert block, state and hashes
        provider_rw.insert_historical_block(
            block
                .clone()
                .try_seal_with_senders()
                .map_err(|_| BlockValidationError::SenderRecoveryError)?,
            None,
        )?;
        block_state.write_to_storage(provider_rw.tx_ref(), None, OriginalValuesKnown::No)?;
        let storage_lists = provider_rw.changed_storages_with_range(block.number..=block.number)?;
        let storages = provider_rw.plain_state_storages(storage_lists)?;
        provider_rw.insert_storage_for_hashing(storages)?;
        let account_lists = provider_rw.changed_accounts_with_range(block.number..=block.number)?;
        let accounts = provider_rw.basic_accounts(account_lists)?;
        provider_rw.insert_account_for_hashing(accounts)?;

        let (state_root, incremental_trie_updates) = StateRoot::incremental_root_with_updates(
            provider_rw.tx_ref(),
            block.number..=block.number,
        )?;
        if state_root != block.state_root {
            eyre::bail!(
                "Computed incremental state root mismatch. Expected: {:?}. Got: {:?}",
                block.state_root,
                state_root
            );
        }

        // Compare updates
        let mut in_mem_mismatched = Vec::new();
        let mut incremental_mismatched = Vec::new();
        let mut in_mem_updates_iter = in_memory_updates.into_iter().peekable();
        let mut incremental_updates_iter = incremental_trie_updates.into_iter().peekable();

        while in_mem_updates_iter.peek().is_some() || incremental_updates_iter.peek().is_some() {
            match (in_mem_updates_iter.next(), incremental_updates_iter.next()) {
                (Some(in_mem), Some(incr)) => {
                    similar_asserts::assert_eq!(in_mem.0, incr.0, "Nibbles don't match");
                    if in_mem.1 != incr.1
                        && matches!(in_mem.0, TrieKey::AccountNode(ref nibbles) if nibbles.0.len() > self.skip_node_depth.unwrap_or_default())
                    {
                        in_mem_mismatched.push(in_mem);
                        incremental_mismatched.push(incr);
                    }
                }
                (Some(in_mem), None) => {
                    warn!(target: "reth::cli", next = ?in_mem, "In-memory trie updates have more entries");
                }
                (None, Some(incr)) => {
                    tracing::warn!(target: "reth::cli", next = ?incr, "Incremental trie updates have more entries");
                }
                (None, None) => {
                    tracing::info!(target: "reth::cli", "Exhausted all trie updates entries");
                }
            }
        }

        similar_asserts::assert_eq!(
            incremental_mismatched,
            in_mem_mismatched,
            "Mismatched trie updates"
        );

        // Drop without committing.
        drop(provider_rw);

        Ok(())
    }
}
