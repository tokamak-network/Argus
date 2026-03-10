# Smart Contract Autopsy Report

**Transaction**: `0x6a00b2d79c49671ca589c817c938ab877a612e335a71f113df1388668d058b50`
**Block**: 24605950
**Total Steps**: 32721

## Summary

**VERDICT: Flash Loan + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation + Price Manipulation detected.** Execution reached depth 4 across 8 contract(s) with 35 external calls. Suspected flash loan provider: `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` (heuristic — first CALL at entry depth). 6 ERC-20 transfer(s) detected. 23 storage write(s).

## Execution Overview

| Metric | Value |
|---|---|
| Max call depth | 4 |
| Unique contracts | 8 |
| CALL/STATICCALL/DELEGATECALL | 35 |
| CREATE/CREATE2 | 0 |
| SLOAD | 84 |
| SSTORE | 23 |
| LOG0-LOG4 | 11 |

**Top opcodes**: PUSHn(9212), DUPn(5190), SWAPn(3262), MLOAD(1870), JUMPI(1806)

## Attack Patterns

10 pattern(s) detected in this transaction.

### Pattern 1 — Flash Loan

- **Suspected provider** (heuristic): `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0`
- **Token**: `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC)
- **Borrow at step**: 11524 (20656526 wei)
- **Repay at step**: 21650 (20656526 wei)

### Pattern 2 — Price Manipulation

- **Oracle read before**: step 9928
- **Swap/manipulation**: step 11524
- **Oracle read after**: step 22568
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 3 — Price Manipulation

- **Oracle read before**: step 10214
- **Swap/manipulation**: step 11524
- **Oracle read after**: step 11876
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 4 — Price Manipulation

- **Oracle read before**: step 11876
- **Swap/manipulation**: step 21650
- **Oracle read after**: step 22248
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 5 — Price Manipulation

- **Oracle read before**: step 12552
- **Swap/manipulation**: step 21650
- **Oracle read after**: step 22248
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 6 — Price Manipulation

- **Oracle read before**: step 22248
- **Swap/manipulation**: step 23327
- **Oracle read after**: step 23623
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 7 — Price Manipulation

- **Oracle read before**: step 22568
- **Swap/manipulation**: step 23327
- **Oracle read after**: step 23978
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 8 — Price Manipulation

- **Oracle read before**: step 23623
- **Swap/manipulation**: step 25676
- **Oracle read after**: step 26403
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 9 — Price Manipulation

- **Oracle read before**: step 25821
- **Swap/manipulation**: step 27765
- **Oracle read after**: step 27931
- **Price delta**: unknown (insufficient SLOAD data)

### Pattern 10 — Price Manipulation

- **Oracle read before**: step 26403
- **Swap/manipulation**: step 27765
- **Oracle read after**: step 28105
- **Price delta**: unknown (insufficient SLOAD data)

## Fund Flow

The following transfers occurred within the flash loan callback span (steps 11524–21650).

| Step | From | To | Value | Token | Event |
|---|---|---|---|---|---|
| 11524 | `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` | `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe` | 20656526 | `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | Transfer |
| 21650 | `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe` | `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | 20656526 | `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | Transfer |
| 22125 | `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe` | 654348343 | `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | Transfer |
| 23327 | `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe` | `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` | 654348343 | `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | Transfer |
| 25676 | `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` | `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | 654348343 | `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | Transfer |
| 27765 | `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` | 157223916794860668668 | `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) | Transfer |

> **Note**: Only ERC-20 Transfer events and ETH value transfers are captured. Flash loan amounts detected via callback analysis are not reflected here.

## Storage Changes

23 storage slot(s) modified during execution.

| Contract | Slot | Old Value | New Value | Interpretation |
|---|---|---|---|---|
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0x0187df93…9110b539` | `0` | `20656526` | New allocation (0 → nonzero) |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0xb178b896…fd9b2c67` | `11879700` | `11879700` | Unchanged |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0x290c785a…92226035` | `0` | `20656526` | New allocation (0 → nonzero) |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0x0187df93…9110b539` | `20656526` | `0` | Cleared (nonzero → 0) |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0xd06ebb73…77c8a1f8` | `0` | `20656526` | New allocation (0 → nonzero) |
| `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | `0x00000000…00ffffff` | `0` | `1` | New allocation (0 → nonzero) |
| `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | `0xb10e2d52…b7fa0cf7` | `52106365` | `52102233` | Decreased |
| `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | `0xb10e2d52…b7fa0cf6` | `1981270100` | `1981658983` | Increased |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0x290c785a…92226035` | `20656526` | `0` | Cleared (nonzero → 0) |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0xcf7f9b16…46b78618` | `52112635` | `52112635` | Unchanged |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | `0xd06ebb73…77c8a1f8` | `20656526` | `0` | Cleared (nonzero → 0) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0xb8c7f54d…0ac7f1f2` | `0` | `1981856577` | New allocation (0 → nonzero) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0x1cdf7e03…7d9ba3f6` | `0` | `654348343` | New allocation (0 → nonzero) |
| `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | `0x00000000…00ffffff` | `1` | `0` | Cleared (nonzero → 0) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0x1cdf7e03…7d9ba3f6` | `654348343` | `0` | Cleared (nonzero → 0) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0xe714324d…dfb0a2f1` | `0` | `654348343` | New allocation (0 → nonzero) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0xe714324d…dfb0a2f1` | `654348343` | `0` | Cleared (nonzero → 0) |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | `0x846cf376…a36ed295` | `0` | `700024807` | New allocation (0 → nonzero) |
| `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | `0x00000000…0000000c` | `1` | `0` | Cleared (nonzero → 0) |
| `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) | `0x96cff41b…6309e2b0` | `10938180599291116954` | `11007962009190893226` | Increased |
| `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) | `0x1a497381…9461442e` | `157294979719973724304` | `157225198310073948032` | Decreased |
| `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | `0x00000000…00000008` | `47797046564031844931851240892638187898874142700787787799518727649926017252762` | `47797048181628644960889628572659093117353001250465757076504851653142279980714` | Increased |
| `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | `0x00000000…0000000c` | `0` | `1` | New allocation (0 → nonzero) |

> Slot decoding requires contract ABI — raw hashes shown (truncated).

## Key Steps

Critical moments in the execution trace:

- [INFO] **Step 9790**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): New allocation (0 → nonzero)
- [WARNING] **Step 9928**: Oracle price read (before manipulation)
- [WARNING] **Step 10214**: Oracle price read (before manipulation)
- [INFO] **Step 11366**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): Unchanged
- [INFO] **Step 11418**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): New allocation (0 → nonzero)
- [INFO] **Step 11490**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): Cleared (nonzero → 0)
- [WARNING] **Step 11524**: Flash loan borrow: 20656526 wei
- [CRITICAL] **Step 11524**: Swap / price manipulation
- [CRITICAL] **Step 11524**: Swap / price manipulation
- [INFO] **Step 11757**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): New allocation (0 → nonzero)
- [WARNING] **Step 11876**: Oracle price read (after manipulation)
- [WARNING] **Step 11876**: Oracle price read (before manipulation)
- [INFO] **Step 12377**: SSTORE on `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: New allocation (0 → nonzero)
- [WARNING] **Step 12552**: Oracle price read (before manipulation)
- [INFO] **Step 21073**: SSTORE on `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: Decreased
- [INFO] **Step 21130**: SSTORE on `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: Increased
- [INFO] **Step 21492**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): Cleared (nonzero → 0)
- [INFO] **Step 21544**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): Unchanged
- [INFO] **Step 21616**: SSTORE on `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): Cleared (nonzero → 0)
- [WARNING] **Step 21650**: Flash loan callback exit / repayment
- [CRITICAL] **Step 21650**: Swap / price manipulation
- [CRITICAL] **Step 21650**: Swap / price manipulation
- [INFO] **Step 22047**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: New allocation (0 → nonzero)
- [INFO] **Step 22103**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: New allocation (0 → nonzero)
- [INFO] **Step 22125**: ERC-20 transfer (`0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`): `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` → `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe`
- [INFO] **Step 22204**: SSTORE on `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: Cleared (nonzero → 0)
- [WARNING] **Step 22248**: Oracle price read (after manipulation)
- [WARNING] **Step 22248**: Oracle price read (after manipulation)
- [WARNING] **Step 22248**: Oracle price read (before manipulation)
- [WARNING] **Step 22568**: Oracle price read (after manipulation)
- [WARNING] **Step 22568**: Oracle price read (before manipulation)
- [INFO] **Step 23249**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: Cleared (nonzero → 0)
- [INFO] **Step 23305**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: New allocation (0 → nonzero)
- [CRITICAL] **Step 23327**: Swap / price manipulation
- [CRITICAL] **Step 23327**: Swap / price manipulation
- [WARNING] **Step 23623**: Oracle price read (after manipulation)
- [WARNING] **Step 23623**: Oracle price read (before manipulation)
- [WARNING] **Step 23978**: Oracle price read (after manipulation)
- [INFO] **Step 25598**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: Cleared (nonzero → 0)
- [INFO] **Step 25654**: SSTORE on `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: New allocation (0 → nonzero)
- [CRITICAL] **Step 25676**: Swap / price manipulation
- [WARNING] **Step 25821**: Oracle price read (before manipulation)
- [WARNING] **Step 26403**: Oracle price read (after manipulation)
- [WARNING] **Step 26403**: Oracle price read (before manipulation)
- [INFO] **Step 27260**: SSTORE on `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: Cleared (nonzero → 0)
- [INFO] **Step 27707**: SSTORE on `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH): Increased
- [INFO] **Step 27738**: SSTORE on `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH): Decreased
- [CRITICAL] **Step 27765**: Swap / price manipulation
- [CRITICAL] **Step 27765**: Swap / price manipulation
- [WARNING] **Step 27931**: Oracle price read (after manipulation)
- [WARNING] **Step 28105**: Oracle price read (after manipulation)
- [INFO] **Step 28778**: SSTORE on `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: Increased
- [INFO] **Step 28863**: SSTORE on `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: New allocation (0 → nonzero)

## Affected Contracts

8 contract(s) involved in this transaction.

| Address | Role |
|---|---|
| `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` | Suspected Flash Loan Provider |
| `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC) | Storage Modified |
| `0xeb4c2781e4eba804ce9a9803c67d0893436bb27d` | Interacted |
| `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80` | Storage Modified |
| `0x2c01b4a79f39a05b44b28b0719ce36c17c483dbe` | Fund Transfer |
| `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714` | Storage Modified |
| `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) | Storage Modified |
| `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3` | Storage Modified |

> Unlabeled contracts require manual identification via block explorer.

## Suggested Fixes

- Validate account solvency after all balance-modifying operations (e.g., donateToReserves, mint, burn).
- Add flash loan protection: ensure functions that destroy collateral check the caller's liquidity position.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.
- Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.
- Add price deviation checks: revert if price moves > X% in a single transaction.

> **Note**: These are generic recommendations based on detected patterns. Analyze the specific vulnerable contract for targeted fixes.

## Conclusion

This transaction exhibits a **Flash Loan** attack pattern. The suspected provider is `0x8bb510a3860e0ad2a0f2794a90cbf14b1b85a2f0` (identified heuristically as the first external CALL at entry depth). The exploit executed within a callback spanning steps 11524–21650 (30% of total execution).A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.A **Price Manipulation** pattern was detected: oracle reads before and after a swap suggest price influence.

**Storage impact:** `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): new allocation (0 → nonzero); `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): unchanged; `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): new allocation (0 → nonzero); `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): cleared (nonzero → 0); `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): new allocation (0 → nonzero); `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: new allocation (0 → nonzero); `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: decreased; `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: increased; `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): cleared (nonzero → 0); `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): unchanged; `0x2260fac5e5542a773aa44fbcfedf7c193bc2c599` (WBTC): cleared (nonzero → 0); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: new allocation (0 → nonzero); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: new allocation (0 → nonzero); `0x7fc77b5c7614e1533320ea6ddc2eb61fa00a9714`: cleared (nonzero → 0); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: cleared (nonzero → 0); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: new allocation (0 → nonzero); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: cleared (nonzero → 0); `0xe2d6ccac3ee3a21abf7bedbe2e107ffc0c037e80`: new allocation (0 → nonzero); `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: cleared (nonzero → 0); `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH): increased; `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH): decreased; `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: increased; `0x81fbef4704776cc5bba0a5df3a90056d2c6900b3`: new allocation (0 → nonzero).

8 contract(s) were involved, with 23 storage modification(s). Manual analysis of the affected contracts is recommended to confirm the attack vector and assess full impact.

---

*This report was generated automatically by the Tokamak Smart Contract Autopsy Lab. Manual analysis is recommended for comprehensive assessment.*
