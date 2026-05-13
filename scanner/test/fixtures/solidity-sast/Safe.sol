// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Safe {
    mapping(address => uint256) public balances;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor() { owner = msg.sender; }

    // Reentrancy-safe: state updated BEFORE external call
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no funds");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "call failed");
    }

    function adminAction() public {
        require(msg.sender == owner, "not owner");
    }

    function kill() public onlyOwner {
        selfdestruct(payable(owner));
    }
}
