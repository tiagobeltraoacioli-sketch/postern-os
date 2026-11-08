// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WBLCH — Wrapped BLCH (the WETH9-equivalent for the Bloch EVM L2)
/// @notice Canonical ERC-20 wrapper for the L2-native gas token (BLCH). Uniswap
///         v2 Pairs require ERC-20 tokens; WBLCH lets native BLCH trade through
///         that interface at a strict 1:1 peg. Deposit native BLCH → receive
///         WBLCH; withdraw WBLCH → receive native BLCH. No custodian, no
///         federation, no outside asset — this wraps ONLY the L2's own native
///         balance (which is itself deposit-minted from Bloch L1 by the rollup;
///         see docs/specs/BLOCH-L2-EVM-DESIGN.md).
///
/// SCOPE (deliberate, per the project's honesty rule): v1 of the bridge does
///         ONLY wBLCH. No wBTC/wETH/wUSDT — outside-asset custody is a separate,
///         later, gated module (docs/specs/BLOCH-BRIDGE-DESIGN.md), NOT this.
///
/// STATUS: UNAUDITED REFERENCE. It cannot be deployed or tested until the Bloch
///         EVM L2 exists (design-only today), and even then it is inert until
///         PosternDex's published activation gate clears (chain security +
///         audit + legal — see posternlabs.com/posterndex). It is a faithful,
///         minimal WETH9-style wrapper and intentionally boring: no owner, no
///         mint privilege, no upgradeability, no fee — supply is exactly the
///         native BLCH escrowed in this contract, always. `totalSupply()` and
///         `address(this).balance` are invariant-equal by construction.
contract WBLCH {
    string public constant name = "Wrapped BLCH";
    string public constant symbol = "WBLCH";
    uint8  public constant decimals = 18; // matches the L2's 18-dp native BLCH

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed to, uint256 value);
    event Withdrawal(address indexed from, uint256 value);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice Wrap native BLCH sent with this call into WBLCH 1:1.
    receive() external payable { deposit(); }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
        emit Transfer(address(0), msg.sender, msg.value);
    }

    /// @notice Burn `wad` WBLCH and receive `wad` native BLCH 1:1.
    function withdraw(uint256 wad) external {
        require(balanceOf[msg.sender] >= wad, "WBLCH: insufficient");
        balanceOf[msg.sender] -= wad;
        emit Transfer(msg.sender, address(0), wad);
        emit Withdrawal(msg.sender, wad);
        (bool ok, ) = msg.sender.call{value: wad}("");
        require(ok, "WBLCH: native transfer failed");
    }

    /// @notice Total WBLCH == native BLCH held == the wrapped supply, always.
    function totalSupply() external view returns (uint256) {
        return address(this).balance;
    }

    function approve(address spender, uint256 wad) external returns (bool) {
        allowance[msg.sender][spender] = wad;
        emit Approval(msg.sender, spender, wad);
        return true;
    }

    function transfer(address to, uint256 wad) external returns (bool) {
        return transferFrom(msg.sender, to, wad);
    }

    function transferFrom(address from, address to, uint256 wad) public returns (bool) {
        require(balanceOf[from] >= wad, "WBLCH: insufficient");
        if (from != msg.sender && allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= wad, "WBLCH: allowance");
            allowance[from][msg.sender] -= wad;
        }
        balanceOf[from] -= wad;
        balanceOf[to] += wad;
        emit Transfer(from, to, wad);
        return true;
    }
}
