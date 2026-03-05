//! Contract labels, opcode names, and display formatting helpers.
//!
//! Extracted from `report.rs` for reuse across the autopsy module and to keep
//! the report generator focused on report structure rather than lookup tables.

use ethrex_common::{Address, H256, U256};

use super::types::AttackPattern;

/// Format an address with a known label if available.
pub fn format_addr(addr: &Address) -> String {
    if let Some(label) = known_label(addr) {
        format!("`0x{addr:x}` ({label})")
    } else {
        format!("`0x{addr:x}`")
    }
}

/// Truncate a storage slot hash for display: `0xabcdef01…89abcdef`.
pub fn truncate_slot(slot: &H256) -> String {
    let hex = format!("{:x}", slot);
    if hex.len() > 16 {
        format!("0x{}…{}", &hex[..8], &hex[hex.len() - 8..])
    } else {
        format!("0x{hex}")
    }
}

/// Human-readable name for an attack pattern variant.
pub fn pattern_name(pattern: &AttackPattern) -> &'static str {
    match pattern {
        AttackPattern::Reentrancy { .. } => "Reentrancy",
        AttackPattern::FlashLoan { .. } => "Flash Loan",
        AttackPattern::PriceManipulation { .. } => "Price Manipulation",
        AttackPattern::AccessControlBypass { .. } => "Access Control Bypass",
    }
}

/// Render detailed Markdown for an attack pattern.
pub fn format_pattern_detail(pattern: &AttackPattern) -> String {
    match pattern {
        AttackPattern::Reentrancy {
            target_contract,
            reentrant_call_step,
            state_modified_step,
            call_depth_at_entry,
        } => {
            format!(
                "- **Target**: {}\n\
                 - **Re-entrant call at step**: {reentrant_call_step}\n\
                 - **State modified at step**: {state_modified_step}\n\
                 - **Entry depth**: {call_depth_at_entry}\n",
                format_addr(target_contract)
            )
        }
        AttackPattern::FlashLoan {
            borrow_step,
            borrow_amount,
            repay_step,
            repay_amount,
            provider,
            token,
        } => {
            let mut detail = String::new();
            if let Some(p) = provider {
                detail.push_str(&format!(
                    "- **Suspected provider** (heuristic): {}\n",
                    format_addr(p)
                ));
            }
            if let Some(t) = token {
                detail.push_str(&format!("- **Token**: {}\n", format_addr(t)));
            }
            if *borrow_amount > U256::zero() {
                detail.push_str(&format!(
                    "- **Borrow at step**: {borrow_step} ({borrow_amount} wei)\n"
                ));
            } else {
                detail.push_str(&format!(
                    "- **Borrow at step**: {borrow_step} (detected via callback depth analysis)\n"
                ));
            }
            if *repay_amount > U256::zero() {
                detail.push_str(&format!(
                    "- **Repay at step**: {repay_step} ({repay_amount} wei)\n"
                ));
            } else {
                detail.push_str(&format!("- **Repay at step**: {repay_step}\n"));
            }
            detail
        }
        AttackPattern::PriceManipulation {
            oracle_read_before,
            swap_step,
            oracle_read_after,
            price_delta_percent,
        } => {
            let delta_str = if *price_delta_percent < 0.0 {
                "unknown (insufficient SLOAD data)".to_string()
            } else {
                format!("{price_delta_percent:.1}%")
            };
            format!(
                "- **Oracle read before**: step {oracle_read_before}\n\
                     - **Swap/manipulation**: step {swap_step}\n\
                     - **Oracle read after**: step {oracle_read_after}\n\
                     - **Price delta**: {delta_str}\n"
            )
        }
        AttackPattern::AccessControlBypass {
            sstore_step,
            contract,
        } => {
            format!(
                "- **SSTORE at step**: {sstore_step}\n\
                 - **Contract**: {}\n",
                format_addr(contract)
            )
        }
    }
}

/// Look up well-known mainnet contract addresses.
///
/// 80+ labels covering stablecoins, DEXes, lending, bridges, oracles,
/// infrastructure, flash loan providers, and MEV contracts.
pub fn known_label(addr: &Address) -> Option<&'static str> {
    let hex = format!("{addr:x}");
    match hex.as_str() {
        // === Stablecoins & tokens ===
        "6b175474e89094c44da98b954eedeac495271d0f" => Some("DAI"),
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" => Some("USDC"),
        "dac17f958d2ee523a2206206994597c13d831ec7" => Some("USDT"),
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => Some("WETH"),
        "2260fac5e5542a773aa44fbcfedf7c193bc2c599" => Some("WBTC"),
        "853d955acef822db058eb8505911ed77f175b99e" => Some("FRAX"),
        "5f98805a4e8be255a32880fdec7f6728c6568ba0" => Some("LUSD"),
        "57ab1ec28d129707052df4df418d58a2d46d5f51" => Some("sUSD"),
        "03ab458634910aad20ef5f1c8ee96f1d6ac54919" => Some("RAI"),
        "056fd409e1d7a124bd7017459dfea2f387b6d5cd" => Some("GUSD"),
        "4fabb145d64652a948d72533023f6e7a623c7c53" => Some("BUSD"),
        "0000000000085d4780b73119b644ae5ecd22b376" => Some("TUSD"),
        "8e870d67f660d95d5be530380d0ec0bd388289e1" => Some("USDP"),
        "1f9840a85d5af5bf1d1762f925bdaddc4201f984" => Some("UNI"),
        "7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9" => Some("AAVE"),
        "514910771af9ca656af840dff83e8264ecf986ca" => Some("LINK"),
        "9f8f72aa9304c8b593d555f12ef6589cc3a579a2" => Some("MKR"),
        "c011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f" => Some("SNX"),
        "d533a949740bb3306d119cc777fa900ba034cd52" => Some("CRV"),
        "ba100000625a3754423978a60c9317c58a424e3d" => Some("BAL"),
        // === Lido ===
        "ae7ab96520de3a18e5e111b5eaab095312d7fe84" => Some("Lido stETH"),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0" => Some("wstETH"),
        // === Aave V2 ===
        "7d2768de32b0b80b7a3454c06bdac94a69ddc7a9" => Some("Aave V2 Pool"),
        "028171bca77440897b824ca71d1c56cac55b68a3" => Some("Aave aDAI"),
        "030ba81f1c18d280636f32af80b9aad02cf0854e" => Some("Aave aWETH"),
        "1982b2f5814301d4e9a8b0201555376e62f82428" => Some("Aave astETH"),
        // === Aave V3 ===
        "87870bca3f3fd6335c3f4ce8392d69350b4fa4e2" => Some("Aave V3 Pool"),
        "2f39d218133afab8f2b819b1066c7e434ad94e9e" => Some("Aave V3 PoolAddressesProvider"),
        // === Morpho ===
        "bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb" => Some("Morpho Blue"),
        // === Spark ===
        "c13e21b648a5ee794902342038ff3adab66be987" => Some("Spark Lending Pool"),
        // === Compound ===
        "4ddc2d193948926d02f9b1fe9e1daa0718270ed5" => Some("Compound cETH"),
        "5d3a536e4d6dbd6114cc1ead35777bab948e3643" => Some("Compound cDAI"),
        "39aa39c021dfbae8fac545936693ac917d5e7563" => Some("Compound cUSDC"),
        "3d9819210a31b4961b30ef54be2aed79b9c9cd3b" => Some("Compound Comptroller"),
        "c3d688b66703497daa19211eedff47f25384cdc3" => Some("Compound V3 cUSDC"),
        // === Uniswap ===
        "7a250d5630b4cf539739df2c5dacb4c659f2488d" => Some("Uniswap V2 Router"),
        "5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f" => Some("Uniswap V2 Factory"),
        "e592427a0aece92de3edee1f18e0157c05861564" => Some("Uniswap V3 Router"),
        "68b3465833fb72a70ecdf485e0e4c7bd8665fc45" => Some("Uniswap V3 Router 02"),
        "1f98431c8ad98523631ae4a59f267346ea31f984" => Some("Uniswap V3 Factory"),
        "c36442b4a4522e871399cd717abdd847ab11fe88" => Some("Uniswap V3 Positions NFT"),
        "000000000022d473030f116ddee9f6b43ac78ba3" => Some("Uniswap Permit2"),
        "3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad" => Some("Uniswap Universal Router"),
        // === SushiSwap ===
        "d9e1ce17f2641f24ae83637ab66a2cca9c378b9f" => Some("SushiSwap Router"),
        // === Curve ===
        "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7" => Some("Curve 3pool"),
        "b9fc157394af804a3578134a6585c0dc9cc990d4" => Some("Curve Factory"),
        "99a58482bd75cbab83b27ec03ca68ff489b5788f" => Some("Curve CryptoSwap Router"),
        // === Balancer ===
        "ba12222222228d8ba445958a75a0704d566bf2c8" => Some("Balancer V2 Vault"),
        // === 1inch ===
        "1111111254eeb25477b68fb85ed929f73a960582" => Some("1inch V5 Router"),
        // === Bridges ===
        "99c9fc46f92e8a1c0dec1b1747d010903e884be1" => Some("Optimism L1 Bridge"),
        "8315177ab297ba92a06054ce80a67ed4dbd7ed3a" => Some("Arbitrum Gateway"),
        "a0c68c638235ee32657e8f720a23cec1bfc6c3d8" => Some("Polygon PoS Bridge"),
        "3ee18b2214aff97000d974cf647e7c347e8fa585" => Some("Wormhole Token Bridge"),
        "40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf" => Some("Polygon ERC20 Bridge"),
        // === Oracles ===
        "5f4ec3df9cbd43714fe2740f5e3616155c5b8419" => Some("Chainlink ETH/USD"),
        "f4030086522a5beea4988f8ca5b36dbc97bee88c" => Some("Chainlink BTC/USD"),
        "2c1d072e956affc0d435cb7ac38ef18d24d9127c" => Some("Chainlink LINK/USD"),
        "8fffffd4afb6115b954bd326cbe7b4ba576818f6" => Some("Chainlink USDC/USD"),
        "47fb2585d2c56fe188d0e6ec628a38b74fceeedf" => Some("Uniswap V3 TWAP Oracle"),
        // === Infrastructure ===
        "ca11bde05977b3631167028862be2a173976ca11" => Some("Multicall3"),
        "4e59b44847b379578588920ca78fbf26c0b4956c" => Some("CREATE2 Deployer"),
        "d9db270c1b5e3bd161e8c8503c55ceabee709552" => Some("Gnosis Safe Singleton"),
        "a2327a938febf5fec13bacfb16ae10ecbc4cc280" => Some("Gnosis Safe ProxyFactory"),
        "c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30001" => Some("EIP-7702 Delegation"),
        // === Flash Loan Providers ===
        "1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e" => Some("dYdX SoloMargin"),
        "27182842e098f60e3d576794a5bffb0777e025d3" => Some("Euler Protocol"),
        "60744434d6339a6b27d73d9eda62b6f66a0a04fa" => Some("Euler SimpleLens"),
        "398ec7346dcd622edc5ae82352f02be94c62d119" => Some("Aave V1 Pool"),
        // === MakerDAO ===
        "9759a6ac90977b93b58547b4a71c78317f391a28" => Some("MakerDAO DSProxy Factory"),
        "5ef30b9986345249bc32d8928b7ee64de9435e39" => Some("MakerDAO Vat"),
        "35d1b3f3d7966a1dfe207aa4514c12a259a0492b" => Some("MakerDAO CDP Manager"),
        // === MEV ===
        "c0ffee254729296a45a3885639ac7e10f9d54979" => Some("MEV Block Builder"),
        "a69babef1ca67a37ffaf7a485dfff3382056e78c" => Some("Flashbots Protect"),
        // === Gnosis Protocol / CoW Swap ===
        "9008d19f58aabd9ed0d60971565aa8510560ab41" => Some("CoW Protocol Settlement"),
        // === ENS ===
        "00000000000c2e074ec69a0dfb2997ba6c7d2e1e" => Some("ENS Registry"),
        "57f1887a8bf19b14fc0df6fd9b2acc9af147ea85" => Some("ENS BaseRegistrar"),
        // === Other Notable Contracts ===
        "c36442b4a4522e871399cd717abdd847ab11fe88..ignored" => None,
        // === Cream Finance (hack-related) ===
        "44fbeb8ea7384d0b58f47e3a92d6dab2a6d8e6a1" => Some("Cream Finance"),
        // === Parity (hack-related) ===
        "863df6bfa4469f3ead0be8f9f2aae51c91a907b4" => Some("Parity Multisig Library"),
        // === Ronin (hack-related) ===
        "1a2a1c938ce3ec39b6d47113c7955baa9dd454f2" => Some("Ronin Gateway"),
        _ => None,
    }
}

/// Interpret a storage value change for human readability.
pub fn interpret_value(old: &U256, new: &U256) -> &'static str {
    if *new == U256::MAX {
        "MAX_UINT256 (infinite approval)"
    } else if old.is_zero() && !new.is_zero() {
        "New allocation (0 → nonzero)"
    } else if !old.is_zero() && new.is_zero() {
        "Cleared (nonzero → 0)"
    } else if *new > *old {
        "Increased"
    } else if *new < *old {
        "Decreased"
    } else {
        "Unchanged"
    }
}

/// Map an EVM opcode byte to its human-readable name.
///
/// PUSHn/DUPn/SWAPn are aggregated by category for frequency analysis.
pub fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x10 => "LT",
        0x11 => "GT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1A => "BYTE",
        0x1B => "SHL",
        0x1C => "SHR",
        0x1D => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3A => "GASPRICE",
        0x3B => "EXTCODESIZE",
        0x3C => "EXTCODECOPY",
        0x3D => "RETURNDATASIZE",
        0x3E => "RETURNDATACOPY",
        0x3F => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5A => "GAS",
        0x5B => "JUMPDEST",
        0x5F => "PUSH0",
        0x60..=0x7F => "PUSHn",
        0x80..=0x8F => "DUPn",
        0x90..=0x9F => "SWAPn",
        0xA0 => "LOG0",
        0xA1 => "LOG1",
        0xA2 => "LOG2",
        0xA3 => "LOG3",
        0xA4 => "LOG4",
        0xF0 => "CREATE",
        0xF1 => "CALL",
        0xF2 => "CALLCODE",
        0xF3 => "RETURN",
        0xF4 => "DELEGATECALL",
        0xF5 => "CREATE2",
        0xFA => "STATICCALL",
        0xFD => "REVERT",
        0xFE => "INVALID",
        0xFF => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}
