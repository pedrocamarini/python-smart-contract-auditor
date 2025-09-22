// Vulnerable.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0; // <-- VULNERABILIDADE! Esta versão é muito antiga.

contract Vulnerable {
    
    uint256 public myNumber;

    function setNumber(uint256 _newNumber) public {
        myNumber = _newNumber;
    }
}