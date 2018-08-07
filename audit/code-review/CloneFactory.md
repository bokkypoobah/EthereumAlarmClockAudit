# CloneFactory

Source file [../../contracts/CloneFactory.sol](../../contracts/CloneFactory.sol).

The original source of this exact version of this code can be found at [https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/contracts/CloneFactory.sol](https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/contracts/CloneFactory.sol).

This is the same contract as listed in [EIP-1167 - Implementation](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1167.md#implementation).

A test factory using CloneFactory has been deployed to Ropsten - the [AFactory](https://ropsten.etherscan.io/address/0x4dc90ef640c82be4f64628e83258f193446295c8#code) factory, the [Code](https://ropsten.etherscan.io/address/0x560f0c45cc562443b45dabc8638b94a795190e3c#code) template, and a [clone of Code](https://ropsten.etherscan.io/address/0x72950534a60bea1db4be1785c4411995426d36b7#code) where the source code is not verified on EtherScan.

The [ContractProbe](https://ropsten.etherscan.io/address/0x75f09888af7c9bdfe15317c411dfb03636179a6d#code) from EIP-1167 above has been deployed to [0x75f09888af7c9bdfe15317c411dfb03636179a6d](https://ropsten.etherscan.io/address/0x75f09888af7c9bdfe15317c411dfb03636179a6d#code) on Ropsten, and can be used to find the original code on which the clones are based upon.

<br />

<hr />

```solidity
// BK Ok
pragma solidity ^0.4.23;

/*
The MIT License (MIT)

Copyright (c) 2018 Murray Software, LLC.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//solhint-disable max-line-length
//solhint-disable no-inline-assembly

// BK Ok
contract CloneFactory {

  // BK Ok - Event
  event CloneCreated(address indexed target, address clone);

  function createClone(address target) internal returns (address result) {
    // BK Ok - See below
    bytes memory clone = hex"600034603b57603080600f833981f36000368180378080368173bebebebebebebebebebebebebebebebebebebebe5af43d82803e15602c573d90f35b3d90fd";
    // BK Ok - Template code address
    bytes20 targetBytes = bytes20(target);
    // BK Next block Ok - Overwrite `beefbeefbeefbeefbeefbeefbeefbeefbeefbeef` with template code address
    for (uint i = 0; i < 20; i++) {
      clone[26 + i] = targetBytes[i];
    }
    assembly {
      // BK NOTE - mload(p) - mem[p..(p+32)). Load word from memory.
      // BK Ok - Len will be 0x3f (63), the number of bytes in clone
      let len := mload(clone)
      // BK NOTE - `data` will point to the start of the `clone` data
      // BK NOTE - In this function, data will be 0xa0 (160)
      let data := add(clone, 0x20)
      // BK Ok - create(v, p, s) - create new contract with code mem[p..(p+s)) and send v wei and return the new address
      result := create(0, data, len)
    }
  }
}

```

<br />

<hr />

## `clone` Bytecode

The `evm` disassembler packaged with `geth` 1.8.12 was used to disassemble the `clone` bytecode in CloneFactory.sol:

```assembly
$ ~/Downloads/geth-alltools-darwin-amd64-1.8.12-37685930/evm disasm clone.asm
600034603b57603080600f833981f36000368180378080368173bebebebebebebebebebebebebebebebebebebebe5af43d82803e15602c573d90f35b3d90fd

// BK NOTE - 0x60 0x00
// BK NOTE - // initialization code
// BK NOTE - evm.push1(0),
000000: PUSH1 0x00

// BK NOTE - 0x34 callvalue - wei sent together with the current call
// BK NOTE - evm.callvalue(),
000002: CALLVALUE

// BK NOTE - 0x60 0x3b
// BK NOTE - 0x3b = 59
// BK NOTE - evm.push1('revert'),
000003: PUSH1 0x3b

// BK NOTE - 0x57 jumpi(label, cond) - jump to label if cond is nonzero
// BK NOTE - evm.jumpi(),
000005: JUMPI

// BK NOTE - 0x60 0x30
// BK NOTE - 0x30 = 48
// BK NOTE - evm.push1('codeend-code'),
000006: PUSH1 0x30

// BK NOTE - 0x80 DUP1 - Duplicate 1st stack item
// BK NOTE - evm.dup1(),
000008: DUP1

// BK NOTE - 0x60 0x0f
// BK NOTE - 0x0f = 15. This is the f parameter for codecopy below, to copy code from 000015
// BK NOTE - evm.push1('code'),
000009: PUSH1 0x0f

// BK NOTE - 0x83 DUP4 Duplicate 4th stack item
// BK NOTE - evm.dup4(),
000011: DUP4

// BK NOTE - 0x39 CODECOPY Copy code running in current environment to memory
// BK NOTE - codecopy(t, f, s) - copy s bytes from code at position f to mem at position t
// BK NOTE - evm.codecopy(),
000012: CODECOPY

// BK NOTE - 0x81 DUP2 - Duplicate 2nd stack item
// BK NOTE - evm.dup2(),
000013: DUP2

// BK NOTE - 0xf3 RETURN - Halt execution returning output data
// BK NOTE - evm.return(),
000014: RETURN


// BK NOTE - evm.label('code'),


// BK NOTE - 0x60 0x00
// BK NOTE - // contract code
// BK NOTE - evm.push1(0),
000015: PUSH1 0x00

// BK NOTE - 0x36 CALLDATASIZE - Get size of input data in current environment
// BK NOTE - evm.calldatasize(), // size of copy
000017: CALLDATASIZE

// BK NOTE - 0x81 DUP2 Duplicate 2nd stack item
// BK NOTE - evm.dup2(), // copy 0 - offset in calldata
000018: DUP2

// BK NOTE - 0x80 DUP1 - Duplicate 1st stack item
// BK NOTE - evm.dup1(), // copy 0x0 - destination location
000019: DUP1

// BK NOTE - 0x37 CALLDATACOPY - Copy input data in current environment to memory
// BK NOTE - calldatacopy(t, f, s) - copy s bytes from calldata at position f to mem at position t
// BK NOTE - evm.calldatacopy(),
000020: CALLDATACOPY

// BK NOTE - 0x80 DUP1 - Duplicate 1st stack item
// BK NOTE - evm.dup1(), // copy 0 - return data size
000021: DUP1

// BK NOTE - 0x80 DUP1 - Duplicate 1st stack item
// BK NOTE - evm.dup1(), // copy 0x0 - return data location
000022: DUP1

// BK NOTE - 0x36 CALLDATASIZE - Get size of input data in current environment
// BK NOTE - evm.calldatasize(), // size of calldata
000023: CALLDATASIZE

// BK NOTE - 0x81 DUP2 Duplicate 2nd stack item
// BK NOTE - evm.dup2(), // copy 0x0 - address of calldata
000024: DUP2

// BK NOTE - 0x73 0xbebebebebebebebebebebebebebebebebebebebe PUSH20 Place 20-byte item on stack
// BK NOTE - evm.label('address'),
// BK NOTE - evm['push' + bytes]('0x' + 'be'.repeat(bytes)), // address placeholder , where bytes = 20
000025: PUSH20 0xbebebebebebebebebebebebebebebebebebebebe

// BK NOTE - 0x5a GAS - Get the amount of available gas, including the corresponding reduction the amount of available gas
// BK NOTE - evm.gas(), // gas budget (all of it)
000046: GAS

// BK NOTE - 0xf4 DELEGATECALL - Message-call into this account with an alternative account's code, but persisting into this account with an alternative account's code
// BK NOTE - delegatecall(g, a, in, insize, out, outsize) - identical to callcode but also keep caller and callvalue
// BK NOTE - callcode(g, a, v, in, insize, out, outsize) - identical to call but only use the code from a and stay in the context of the current contract otherwise
// BK NOTE - call(g, a, v, in, insize, out, outsize) - call contract at address a with input mem[in..(in+insize)) providing g gas and v wei and output area mem[out..(out+outsize)) returning 0 on error (eg. out of gas) and 1 on success
// BK NOTE - evm.delegatecall(),
000047: DELEGATECALL

// BK NOTE - 0x3d RETURNDATASIZE - Pushes the size of the return data buffer onto the stack
// BK NOTE - evm.returndatasize(), // size of copy
000048: RETURNDATASIZE

// BK NOTE - 0x82 DUP3 Duplicate 3rd stack item
// BK NOTE - evm.dup3(), // copy 0 - offset in return data
000049: DUP3

// BK NOTE - 0x80 DUP1 - Duplicate 1st stack item
// BK NOTE - evm.dup1(), // copy 0x0 - destination location
000050: DUP1

// BK NOTE - 0x3e RETURNDATACOPY - Copies data from the return data buffer to memory
// BK NOTE - evm.returndatacopy(),
000051: RETURNDATACOPY

// BK NOTE - 0x15 ISZERO - Simple not operator
// BK NOTE - evm.iszero(), // check return value
000052: ISZERO

// BK NOTE - 0x60 0x2c
// BK NOTE - 0x2c = 44. 44 + 15 (start of code) = 59 which is 000059: JUMPDEST below
// BK NOTE - evm.push1('revert-code'), // revert address (in code address space)
000053: PUSH1 0x2c

// BK NOTE - 0x57 jumpi(label, cond) - jump to label if cond is nonzero
// BK NOTE - evm.jumpi(), // revert if zero
000055: JUMPI

// BK NOTE - 0x3d RETURNDATASIZE - Pushes the size of the return data buffer onto the stack
// BK NOTE - evm.returndatasize(), // length of return data
000056: RETURNDATASIZE

// BK NOTE - 0x90 SWAP1 - Exchange 1st and 2nd stack items
// BK NOTE - evm.swap1(), // pull up 0x0 - location of return data
000057: SWAP1

// BK NOTE - 0xf3 RETURN - Halt execution returning output data
// BK NOTE - evm.return(),
000058: RETURN

// BK NOTE - JUMPI from 000005 will jump here if condition is non-zero
// BK NOTE - JUMPI from 000055 will also jump here is condition is non-zero
// BK NOTE - 0x5b JUMPDEST Mark a valid destination for jumps
// BK NOTE - evm.jumpdest('revert'),
000059: JUMPDEST

// BK NOTE - 0x3d RETURNDATASIZE - Pushes the size of the return data buffer onto the stack
// BK NOTE - evm.returndatasize(), // length of return data
000060: RETURNDATASIZE

// BK NOTE - 0x90 SWAP1 - Exchange 1st and 2nd stack items
// BK NOTE - evm.swap1(), // pull up 0x0 - revert data location
000061: SWAP1

// BK NOTE - 0xfd REVERT - Stop execution and revert state changes, without consuming all provided gas and providing a reason
// BK NOTE - evm.revert(),
000062: REVERT

// BK NOTE - // end label
// BK NOTE - evm.label('codeend')
```

<br />

<hr />

## `clone` Bytecode Generator

From [https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/clone-contract.js](https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/clone-contract.js):

```solidity
const evm = require('@optionality.io/evm-asm');

module.exports = (bytes = 20) => evm.program([

  // initialization code
  evm.push1(0),
  evm.callvalue(),
  evm.push1('revert'),
  evm.jumpi(),
  evm.push1('codeend-code'),
  evm.dup1(),
  evm.push1('code'),
  evm.dup4(),
  evm.codecopy(),
  evm.dup2(),
  evm.return(),
  evm.label('code'),


  // contract code
  evm.push1(0),
  evm.calldatasize(), // size of copy
  evm.dup2(), // copy 0 - offset in calldata
  evm.dup1(), // copy 0x0 - destination location
  evm.calldatacopy(),
  evm.dup1(), // copy 0 - return data size
  evm.dup1(), // copy 0x0 - return data location
  evm.calldatasize(), // size of calldata
  evm.dup2(), // copy 0x0 - address of calldata
  evm.label('address'),
  evm['push' + bytes]('0x' + 'be'.repeat(bytes)), // address placeholder
  evm.gas(), // gas budget (all of it)
  evm.delegatecall(),
  evm.returndatasize(), // size of copy
  evm.dup3(), // copy 0 - offset in return data
  evm.dup1(), // copy 0x0 - destination location
  evm.returndatacopy(),
  evm.iszero(), // check return value
  evm.push1('revert-code'), // revert address (in code address space)
  evm.jumpi(), // revert if zero
  evm.returndatasize(), // length of return data
  evm.swap1(), // pull up 0x0 - location of return data
  evm.return(),
  evm.jumpdest('revert'),
  evm.returndatasize(), // length of return data
  evm.swap1(), // pull up 0x0 - revert data location
  evm.revert(),

  // end label
  evm.label('codeend')
]);
```

<br />

<hr />

## References

* [Ethereum Yellow Paper](http://gavwood.com/paper.pdf)
* [Solidity Assembly](http://solidity.readthedocs.io/en/v0.4.21/assembly.html)
* [EVM Opcodes](https://github.com/trailofbits/evm-opcodes)
