//! Unit tests for `find_prior_same_sender_txs` and `replay_prior_txs`.
//!
//! All tests run offline (no RPC calls). Mock `RpcTransaction` instances are
//! created via the `make_rpc_tx` helper.

#[cfg(feature = "autopsy")]
mod tests {
    use ethrex_common::{Address, H256, U256};

    use crate::autopsy::rpc_client::{RpcBlockHeader, RpcTransaction};
    use crate::engine::{find_prior_same_sender_txs, replay_prior_txs};

    // ── Helpers ─────────────────────────────────────────────────────

    /// Create a minimal `RpcTransaction` for testing.
    fn make_rpc_tx(from: Address, hash_byte: u8, nonce: u64) -> RpcTransaction {
        RpcTransaction {
            hash: H256::from([hash_byte; 32]),
            from,
            to: Some(Address::zero()),
            value: U256::zero(),
            input: Vec::new(),
            gas: 21_000,
            gas_price: Some(1_000_000_000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce,
            block_number: Some(1),
        }
    }

    fn alice() -> Address {
        Address::from([0xAA; 20])
    }

    fn bob() -> Address {
        Address::from([0xBB; 20])
    }

    /// Create a minimal block header for replay tests.
    fn make_block_header() -> RpcBlockHeader {
        RpcBlockHeader {
            hash: H256::zero(),
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            coinbase: Address::zero(),
        }
    }

    // ── find_prior_same_sender_txs tests ────────────────────────────

    #[test]
    fn test_find_prior_same_sender_txs_empty_block() {
        // Empty block TX list, target at index 0 → empty result
        let target = make_rpc_tx(alice(), 0x01, 0);
        let block_txs: Vec<RpcTransaction> = vec![];
        let result = find_prior_same_sender_txs(&block_txs, &target);
        assert!(result.is_empty(), "expected empty Vec for empty block");
    }

    #[test]
    fn test_find_prior_same_sender_txs_no_prior() {
        // Target is the first TX from alice — no prior TXs from same sender
        let tx_a = make_rpc_tx(alice(), 0x01, 0);
        let tx_b = make_rpc_tx(bob(), 0x02, 0);
        let block_txs = vec![tx_a.clone(), tx_b];
        let result = find_prior_same_sender_txs(&block_txs, &tx_a);
        assert!(
            result.is_empty(),
            "first TX from sender should have no priors"
        );
    }

    #[test]
    fn test_find_prior_same_sender_txs_multiple() {
        // [TX_A(alice), TX_B(bob), TX_C(alice), TX_D(alice)]
        // target = TX_D → expect [TX_A, TX_C] in order
        let tx_a = make_rpc_tx(alice(), 0x01, 10);
        let tx_b = make_rpc_tx(bob(), 0x02, 20);
        let tx_c = make_rpc_tx(alice(), 0x03, 11);
        let tx_d = make_rpc_tx(alice(), 0x04, 12);
        let block_txs = vec![tx_a.clone(), tx_b, tx_c.clone(), tx_d.clone()];

        let result = find_prior_same_sender_txs(&block_txs, &tx_d);
        assert_eq!(result.len(), 2, "expected 2 prior TXs from alice");
        assert_eq!(result[0].hash, tx_a.hash, "first prior should be TX_A");
        assert_eq!(result[1].hash, tx_c.hash, "second prior should be TX_C");
    }

    // ── replay_prior_txs tests ──────────────────────────────────────

    #[test]
    fn test_replay_prior_txs_empty() {
        // Empty prior_txs → empty results, no VM calls
        let block_header = make_block_header();
        let mut db = crate::tests::helpers::make_test_db(vec![]);
        let results = replay_prior_txs(&mut db, &block_header, &[], 10);
        assert!(results.is_empty(), "expected empty Vec for empty prior_txs");
    }

    #[test]
    fn test_replay_prior_txs_respects_max_prior_txs() {
        // 3 prior TXs with max_prior_txs=2 → only 2 results
        use bytes::Bytes;
        use ethrex_common::types::Code;

        let sender = alice();

        // Create DB with sender account (has balance for gas)
        let accounts = vec![crate::tests::helpers::TestAccount {
            address: sender,
            code: Code::from_bytecode(Bytes::new()),
        }];
        let mut db = crate::tests::helpers::make_test_db(accounts);

        let block_header = make_block_header();

        // 3 simple transfer TXs from alice
        let prior_txs = vec![
            make_rpc_tx(sender, 0x01, 0),
            make_rpc_tx(sender, 0x02, 1),
            make_rpc_tx(sender, 0x03, 2),
        ];

        let results = replay_prior_txs(&mut db, &block_header, &prior_txs, 2);
        assert_eq!(
            results.len(),
            2,
            "should only replay max_prior_txs=2, got {}",
            results.len()
        );
        assert_eq!(results[0].tx_hash, prior_txs[0].hash);
        assert!(
            results[0].success,
            "TX[0] should succeed: sender has U256::MAX balance"
        );
        assert_eq!(results[1].tx_hash, prior_txs[1].hash);
        assert!(
            results[1].success,
            "TX[1] should succeed: sender has U256::MAX balance"
        );
    }
}
