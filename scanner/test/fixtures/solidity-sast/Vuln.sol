// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Vuln {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    // Reentrancy: external call before state update
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no funds");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }

    // tx.origin auth
    function adminAction() public {
        require(tx.origin == owner, "not owner");
    }

    // block.timestamp as RNG
    function lottery(address picker) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, picker));
    }

    // selfdestruct without owner check
    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    // delegatecall to user-controlled address
    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
