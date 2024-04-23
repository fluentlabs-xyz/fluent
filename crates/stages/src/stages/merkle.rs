use crate::{BlockErrorKind, ExecInput, ExecOutput, Stage, StageError, UnwindInput, UnwindOutput};
use reth_codecs::Compact;
use reth_db::{
    database::Database,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_interfaces::consensus;
use reth_primitives::{
    stage::{EntitiesCheckpoint, MerkleCheckpoint, StageCheckpoint, StageId},
    trie::StoredSubNode,
    BlockNumber, GotExpected, SealedHeader, B256,
};
use reth_provider::{
    DatabaseProviderRW, HeaderProvider, ProviderError, StageCheckpointReader,
    StageCheckpointWriter, StatsReader,
};
use reth_trie::{IntermediateStateRootState, StateRoot, StateRootProgress};
use std::fmt::Debug;
use tracing::*;

/// The default threshold (in number of blocks) for switching from incremental trie building
/// of changes to whole rebuild.
pub const MERKLE_STAGE_DEFAULT_CLEAN_THRESHOLD: u64 = 5_000;

/// The merkle hashing stage uses input from
/// [`AccountHashingStage`][crate::stages::AccountHashingStage] and
/// [`StorageHashingStage`][crate::stages::AccountHashingStage] to calculate intermediate hashes
/// and state roots.
///
/// This stage should be run with the above two stages, otherwise it is a no-op.
///
/// This stage is split in two: one for calculating hashes and one for unwinding.
///
/// When run in execution, it's going to be executed AFTER the hashing stages, to generate
/// the state root. When run in unwind mode, it's going to be executed BEFORE the hashing stages,
/// so that it unwinds the intermediate hashes based on the unwound hashed state from the hashing
/// stages. The order of these two variants is important. The unwind variant should be added to the
/// pipeline before the execution variant.
///
/// An example pipeline to only hash state would be:
///
/// - [`MerkleStage::Unwind`]
/// - [`AccountHashingStage`][crate::stages::AccountHashingStage]
/// - [`StorageHashingStage`][crate::stages::StorageHashingStage]
/// - [`MerkleStage::Execution`]
#[derive(Debug, Clone)]
pub enum MerkleStage {
    /// The execution portion of the merkle stage.
    Execution {
        /// The threshold (in number of blocks) for switching from incremental trie building
        /// of changes to whole rebuild.
        clean_threshold: u64,
    },
    /// The unwind portion of the merkle stage.
    Unwind,
    /// Able to execute and unwind. Used for tests
    #[cfg(any(test, feature = "test-utils"))]
    Both {
        /// The threshold (in number of blocks) for switching from incremental trie building
        /// of changes to whole rebuild.
        clean_threshold: u64,
    },
}

impl MerkleStage {
    /// Stage default for the [MerkleStage::Execution].
    pub fn default_execution() -> Self {
        Self::Execution { clean_threshold: MERKLE_STAGE_DEFAULT_CLEAN_THRESHOLD }
    }

    /// Stage default for the [MerkleStage::Unwind].
    pub fn default_unwind() -> Self {
        Self::Unwind
    }

    /// Create new instance of [MerkleStage::Execution].
    pub fn new_execution(clean_threshold: u64) -> Self {
        Self::Execution { clean_threshold }
    }

    /// Gets the hashing progress
    pub fn get_execution_checkpoint<DB: Database>(
        &self,
        provider: &DatabaseProviderRW<DB>,
    ) -> Result<Option<MerkleCheckpoint>, StageError> {
        let buf =
            provider.get_stage_checkpoint_progress(StageId::MerkleExecute)?.unwrap_or_default();

        if buf.is_empty() {
            return Ok(None);
        }

        let (checkpoint, _) = MerkleCheckpoint::from_compact(&buf, buf.len());
        Ok(Some(checkpoint))
    }

    /// Saves the hashing progress
    pub fn save_execution_checkpoint<DB: Database>(
        &mut self,
        provider: &DatabaseProviderRW<DB>,
        checkpoint: Option<MerkleCheckpoint>,
    ) -> Result<(), StageError> {
        let mut buf = vec![];
        if let Some(checkpoint) = checkpoint {
            debug!(
                target: "sync::stages::merkle::exec",
                last_account_key = ?checkpoint.last_account_key,
                "Saving inner merkle checkpoint"
            );
            checkpoint.to_compact(&mut buf);
        }
        Ok(provider.save_stage_checkpoint_progress(StageId::MerkleExecute, buf)?)
    }
}

impl<DB: Database> Stage<DB> for MerkleStage {
    /// Return the id of the stage
    fn id(&self) -> StageId {
        match self {
            MerkleStage::Execution { .. } => StageId::MerkleExecute,
            MerkleStage::Unwind => StageId::MerkleUnwind,
            #[cfg(any(test, feature = "test-utils"))]
            MerkleStage::Both { .. } => StageId::Other("MerkleBoth"),
        }
    }

    /// Execute the stage.
    fn execute(
        &mut self,
        provider: &DatabaseProviderRW<DB>,
        input: ExecInput,
    ) -> Result<ExecOutput, StageError> {
        let threshold = match self {
            MerkleStage::Unwind => {
                info!(target: "sync::stages::merkle::unwind", "Stage is always skipped");
                return Ok(ExecOutput::done(StageCheckpoint::new(input.target())));
            }
            MerkleStage::Execution { clean_threshold } => *clean_threshold,
            #[cfg(any(test, feature = "test-utils"))]
            MerkleStage::Both { clean_threshold } => *clean_threshold,
        };

        let range = input.next_block_range();
        let (from_block, to_block) = range.clone().into_inner();
        let current_block_number = input.checkpoint().block_number;

        let target_block = provider
            .header_by_number(to_block)?
            .ok_or_else(|| ProviderError::HeaderNotFound(to_block.into()))?;
        let target_block_root = target_block.state_root;

        let mut checkpoint = self.get_execution_checkpoint(provider)?;
        let (trie_root, entities_checkpoint) = if range.is_empty() {
            (target_block_root, input.checkpoint().entities_stage_checkpoint().unwrap_or_default())
        } else if to_block - from_block > threshold || from_block == 1 {
            // if there are more blocks than threshold it is faster to rebuild the trie
            let mut entities_checkpoint = if let Some(checkpoint) =
                checkpoint.as_ref().filter(|c| c.target_block == to_block)
            {
                debug!(
                    target: "sync::stages::merkle::exec",
                    current = ?current_block_number,
                    target = ?to_block,
                    last_account_key = ?checkpoint.last_account_key,
                    "Continuing inner merkle checkpoint"
                );

                input.checkpoint().entities_stage_checkpoint()
            } else {
                debug!(
                    target: "sync::stages::merkle::exec",
                    current = ?current_block_number,
                    target = ?to_block,
                    previous_checkpoint = ?checkpoint,
                    "Rebuilding trie"
                );
                // Reset the checkpoint and clear trie tables
                checkpoint = None;
                self.save_execution_checkpoint(provider, None)?;
                provider.tx_ref().clear::<tables::AccountsTrie>()?;
                provider.tx_ref().clear::<tables::StoragesTrie>()?;

                None
            }
            .unwrap_or(EntitiesCheckpoint {
                processed: 0,
                total: (provider.count_entries::<tables::HashedAccounts>()?
                    + provider.count_entries::<tables::HashedStorages>()?)
                    as u64,
            });

            let tx = provider.tx_ref();
            let progress = StateRoot::from_tx(tx)
                .with_intermediate_state(checkpoint.map(IntermediateStateRootState::from))
                .root_with_progress()
                .map_err(|e| StageError::Fatal(Box::new(e)))?;
            match progress {
                StateRootProgress::Progress(state, hashed_entries_walked, updates) => {
                    updates.flush(tx)?;

                    let checkpoint = MerkleCheckpoint::new(
                        to_block,
                        state.last_account_key,
                        state.walker_stack.into_iter().map(StoredSubNode::from).collect(),
                        state.hash_builder.into(),
                    );
                    self.save_execution_checkpoint(provider, Some(checkpoint))?;

                    entities_checkpoint.processed += hashed_entries_walked as u64;

                    return Ok(ExecOutput {
                        checkpoint: input
                            .checkpoint()
                            .with_entities_stage_checkpoint(entities_checkpoint),
                        done: false,
                    });
                }
                StateRootProgress::Complete(root, hashed_entries_walked, updates) => {
                    updates.flush(tx)?;

                    entities_checkpoint.processed += hashed_entries_walked as u64;

                    (root, entities_checkpoint)
                }
            }
        } else {
            debug!(target: "sync::stages::merkle::exec", current = ?current_block_number, target = ?to_block, "Updating trie");
            let (root, updates) =
                StateRoot::incremental_root_with_updates(provider.tx_ref(), range)
                    .map_err(|e| StageError::Fatal(Box::new(e)))?;
            updates.flush(provider.tx_ref())?;

            let total_hashed_entries = (provider.count_entries::<tables::HashedAccounts>()?
                + provider.count_entries::<tables::HashedStorages>()?)
                as u64;

            let entities_checkpoint = EntitiesCheckpoint {
                // This is fine because `range` doesn't have an upper bound, so in this `else`
                // branch we're just hashing all remaining accounts and storage slots we have in the
                // database.
                processed: total_hashed_entries,
                total: total_hashed_entries,
            };

            (root, entities_checkpoint)
        };

        // Reset the checkpoint
        self.save_execution_checkpoint(provider, None)?;

        validate_state_root(trie_root, target_block.seal_slow(), to_block)?;

        Ok(ExecOutput {
            checkpoint: StageCheckpoint::new(to_block)
                .with_entities_stage_checkpoint(entities_checkpoint),
            done: true,
        })
    }

    /// Unwind the stage.
    fn unwind(
        &mut self,
        provider: &DatabaseProviderRW<DB>,
        input: UnwindInput,
    ) -> Result<UnwindOutput, StageError> {
        let tx = provider.tx_ref();
        let range = input.unwind_block_range();
        if matches!(self, MerkleStage::Execution { .. }) {
            info!(target: "sync::stages::merkle::unwind", "Stage is always skipped");
            return Ok(UnwindOutput { checkpoint: StageCheckpoint::new(input.unwind_to) });
        }

        let mut entities_checkpoint =
            input.checkpoint.entities_stage_checkpoint().unwrap_or(EntitiesCheckpoint {
                processed: 0,
                total: (tx.entries::<tables::HashedAccounts>()?
                    + tx.entries::<tables::HashedStorages>()?) as u64,
            });

        if input.unwind_to == 0 {
            tx.clear::<tables::AccountsTrie>()?;
            tx.clear::<tables::StoragesTrie>()?;

            entities_checkpoint.processed = 0;

            return Ok(UnwindOutput {
                checkpoint: StageCheckpoint::new(input.unwind_to)
                    .with_entities_stage_checkpoint(entities_checkpoint),
            });
        }

        // Unwind trie only if there are transitions
        if !range.is_empty() {
            let (block_root, updates) = StateRoot::incremental_root_with_updates(tx, range)
                .map_err(|e| StageError::Fatal(Box::new(e)))?;

            // Validate the calculated state root
            let target = provider
                .header_by_number(input.unwind_to)?
                .ok_or_else(|| ProviderError::HeaderNotFound(input.unwind_to.into()))?;
            validate_state_root(block_root, target.seal_slow(), input.unwind_to)?;

            // Validation passed, apply unwind changes to the database.
            updates.flush(provider.tx_ref())?;

            // TODO(alexey): update entities checkpoint
        } else {
            info!(target: "sync::stages::merkle::unwind", "Nothing to unwind");
        }

        Ok(UnwindOutput { checkpoint: StageCheckpoint::new(input.unwind_to) })
    }
}

/// Check that the computed state root matches the root in the expected header.
#[inline]
fn validate_state_root(
    got: B256,
    expected: SealedHeader,
    target_block: BlockNumber,
) -> Result<(), StageError> {
    if got == expected.state_root {
        Ok(())
    } else {
        warn!(target: "sync::stages::merkle", ?target_block, ?got, ?expected, "Failed to verify block state root");
        Err(StageError::Block {
            error: BlockErrorKind::Validation(consensus::ConsensusError::BodyStateRootDiff(
                GotExpected { got, expected: expected.state_root }.into(),
            )),
            block: Box::new(expected),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        stage_test_suite_ext, ExecuteStageTestRunner, StageTestRunner, StorageKind,
        TestRunnerError, TestStageDB, UnwindStageTestRunner,
    };
    use assert_matches::assert_matches;
    use reth_db::cursor::{DbCursorRO, DbCursorRW, DbDupCursorRO};
    use reth_interfaces::test_utils::{
        generators,
        generators::{
            random_block, random_block_range, random_changeset_range, random_contract_account_range,
        },
    };
    use reth_primitives::{
        keccak256, stage::StageUnitCheckpoint, SealedBlock, StaticFileSegment, StorageEntry, U256,
    };
    use reth_provider::providers::StaticFileWriter;
    use reth_trie::test_utils::{state_root, state_root_prehashed};
    use std::collections::BTreeMap;

    stage_test_suite_ext!(MerkleTestRunner, merkle);

    /// Execute from genesis so as to merkelize whole state
    #[tokio::test]
    async fn execute_clean_merkle() {
        let (previous_stage, stage_progress) = (500, 0);

        // Set up the runner
        let mut runner = MerkleTestRunner::default();
        // set low threshold so we hash the whole storage
        let input = ExecInput {
            target: Some(previous_stage),
            checkpoint: Some(StageCheckpoint::new(stage_progress)),
        };

        runner.seed_execution(input).expect("failed to seed execution");

        let rx = runner.execute(input);

        // Assert the successful result
        let result = rx.await.unwrap();
        assert_matches!(
            result,
            Ok(ExecOutput {
                checkpoint: StageCheckpoint {
                    block_number,
                    stage_checkpoint: Some(StageUnitCheckpoint::Entities(EntitiesCheckpoint {
                        processed,
                        total
                    }))
                },
                done: true
            }) if block_number == previous_stage && processed == total &&
                total == (
                    runner.db.table::<tables::HashedAccounts>().unwrap().len() +
                    runner.db.table::<tables::HashedStorages>().unwrap().len()
                ) as u64
        );

        // Validate the stage execution
        assert!(runner.validate_execution(input, result.ok()).is_ok(), "execution validation");
    }

    /// Update small trie
    #[tokio::test]
    async fn execute_small_merkle() {
        let (previous_stage, stage_progress) = (2, 1);

        // Set up the runner
        let mut runner = MerkleTestRunner::default();
        let input = ExecInput {
            target: Some(previous_stage),
            checkpoint: Some(StageCheckpoint::new(stage_progress)),
        };

        runner.seed_execution(input).expect("failed to seed execution");

        let rx = runner.execute(input);

        // Assert the successful result
        let result = rx.await.unwrap();
        assert_matches!(
            result,
            Ok(ExecOutput {
                checkpoint: StageCheckpoint {
                    block_number,
                    stage_checkpoint: Some(StageUnitCheckpoint::Entities(EntitiesCheckpoint {
                        processed,
                        total
                    }))
                },
                done: true
            }) if block_number == previous_stage && processed == total &&
                total == (
                    runner.db.table::<tables::HashedAccounts>().unwrap().len() +
                    runner.db.table::<tables::HashedStorages>().unwrap().len()
                ) as u64
        );

        // Validate the stage execution
        assert!(runner.validate_execution(input, result.ok()).is_ok(), "execution validation");
    }

    struct MerkleTestRunner {
        db: TestStageDB,
        clean_threshold: u64,
    }

    impl Default for MerkleTestRunner {
        fn default() -> Self {
            Self { db: TestStageDB::default(), clean_threshold: 10000 }
        }
    }

    impl StageTestRunner for MerkleTestRunner {
        type S = MerkleStage;

        fn db(&self) -> &TestStageDB {
            &self.db
        }

        fn stage(&self) -> Self::S {
            Self::S::Both { clean_threshold: self.clean_threshold }
        }
    }

    impl ExecuteStageTestRunner for MerkleTestRunner {
        type Seed = Vec<SealedBlock>;

        fn seed_execution(&mut self, input: ExecInput) -> Result<Self::Seed, TestRunnerError> {
            let stage_progress = input.checkpoint().block_number;
            let start = stage_progress + 1;
            let end = input.target();
            let mut rng = generators::rng();

            let mut preblocks = vec![];
            if stage_progress > 0 {
                preblocks.append(&mut random_block_range(
                    &mut rng,
                    0..=stage_progress - 1,
                    B256::ZERO,
                    0..1,
                ));
                self.db.insert_blocks(preblocks.iter(), StorageKind::Static)?;
            }

            let num_of_accounts = 31;
            let accounts = random_contract_account_range(&mut rng, &mut (0..num_of_accounts))
                .into_iter()
                .collect::<BTreeMap<_, _>>();

            self.db.insert_accounts_and_storages(
                accounts.iter().map(|(addr, acc)| (*addr, (*acc, std::iter::empty()))),
            )?;

            let SealedBlock { header, body, ommers, withdrawals } = random_block(
                &mut rng,
                stage_progress,
                preblocks.last().map(|b| b.hash()),
                Some(0),
                None,
            );
            let mut header = header.unseal();

            header.state_root = state_root(
                accounts
                    .clone()
                    .into_iter()
                    .map(|(address, account)| (address, (account, std::iter::empty()))),
            );
            let sealed_head = SealedBlock { header: header.seal_slow(), body, ommers, withdrawals };

            let head_hash = sealed_head.hash();
            let mut blocks = vec![sealed_head];
            blocks.extend(random_block_range(&mut rng, start..=end, head_hash, 0..3));
            let last_block = blocks.last().cloned().unwrap();
            self.db.insert_blocks(blocks.iter(), StorageKind::Static)?;

            let (transitions, final_state) = random_changeset_range(
                &mut rng,
                blocks.iter(),
                accounts.into_iter().map(|(addr, acc)| (addr, (acc, Vec::new()))),
                0..3,
                0..256,
            );
            // add block changeset from block 1.
            self.db.insert_changesets(transitions, Some(start))?;
            self.db.insert_accounts_and_storages(final_state)?;

            // Calculate state root
            let root = self.db.query(|tx| {
                let mut accounts = BTreeMap::default();
                let mut accounts_cursor = tx.cursor_read::<tables::HashedAccounts>()?;
                let mut storage_cursor = tx.cursor_dup_read::<tables::HashedStorages>()?;
                for entry in accounts_cursor.walk_range(..)? {
                    let (key, account) = entry?;
                    let mut storage_entries = Vec::new();
                    let mut entry = storage_cursor.seek_exact(key)?;
                    while let Some((_, storage)) = entry {
                        storage_entries.push(storage);
                        entry = storage_cursor.next_dup()?;
                    }
                    let storage = storage_entries
                        .into_iter()
                        .filter(|v| v.value != U256::ZERO)
                        .map(|v| (v.key, v.value))
                        .collect::<Vec<_>>();
                    accounts.insert(key, (account, storage));
                }

                Ok(state_root_prehashed(accounts.into_iter()))
            })?;

            let static_file_provider = self.db.factory.static_file_provider();
            let mut writer =
                static_file_provider.latest_writer(StaticFileSegment::Headers).unwrap();
            let mut last_header = last_block.header().clone();
            last_header.state_root = root;

            let hash = last_header.hash_slow();
            writer.prune_headers(1).unwrap();
            writer.append_header(last_header, U256::ZERO, hash).unwrap();
            writer.commit().unwrap();

            Ok(blocks)
        }

        fn validate_execution(
            &self,
            _input: ExecInput,
            _output: Option<ExecOutput>,
        ) -> Result<(), TestRunnerError> {
            // The execution is validated within the stage
            Ok(())
        }
    }

    impl UnwindStageTestRunner for MerkleTestRunner {
        fn validate_unwind(&self, _input: UnwindInput) -> Result<(), TestRunnerError> {
            // The unwind is validated within the stage
            Ok(())
        }

        fn before_unwind(&self, input: UnwindInput) -> Result<(), TestRunnerError> {
            let target_block = input.unwind_to + 1;

            self.db
                .commit(|tx| {
                    let mut storage_changesets_cursor =
                        tx.cursor_dup_read::<tables::StorageChangeSets>().unwrap();
                    let mut storage_cursor =
                        tx.cursor_dup_write::<tables::HashedStorages>().unwrap();

                    let mut tree: BTreeMap<B256, BTreeMap<B256, U256>> = BTreeMap::new();

                    let mut rev_changeset_walker =
                        storage_changesets_cursor.walk_back(None).unwrap();
                    while let Some((bn_address, entry)) =
                        rev_changeset_walker.next().transpose().unwrap()
                    {
                        if bn_address.block_number() < target_block {
                            break;
                        }

                        tree.entry(keccak256(bn_address.address()))
                            .or_default()
                            .insert(keccak256(entry.key), entry.value);
                    }
                    for (hashed_address, storage) in tree.into_iter() {
                        for (hashed_slot, value) in storage.into_iter() {
                            let storage_entry = storage_cursor
                                .seek_by_key_subkey(hashed_address, hashed_slot)
                                .unwrap();
                            if storage_entry.map(|v| v.key == hashed_slot).unwrap_or_default() {
                                storage_cursor.delete_current().unwrap();
                            }

                            if value != U256::ZERO {
                                let storage_entry = StorageEntry { key: hashed_slot, value };
                                storage_cursor.upsert(hashed_address, storage_entry).unwrap();
                            }
                        }
                    }

                    let mut changeset_cursor =
                        tx.cursor_dup_write::<tables::AccountChangeSets>().unwrap();
                    let mut rev_changeset_walker = changeset_cursor.walk_back(None).unwrap();

                    while let Some((block_number, account_before_tx)) =
                        rev_changeset_walker.next().transpose().unwrap()
                    {
                        if block_number < target_block {
                            break;
                        }

                        if let Some(acc) = account_before_tx.info {
                            tx.put::<tables::HashedAccounts>(
                                keccak256(account_before_tx.address),
                                acc,
                            )
                            .unwrap();
                        } else {
                            tx.delete::<tables::HashedAccounts>(
                                keccak256(account_before_tx.address),
                                None,
                            )
                            .unwrap();
                        }
                    }
                    Ok(())
                })
                .unwrap();
            Ok(())
        }
    }
}
