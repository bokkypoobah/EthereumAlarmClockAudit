# CloneFactory

Source file [../../contracts/CloneFactory.sol](../../contracts/CloneFactory.sol).

The original source of this exact version of this code can be found at [https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/contracts/CloneFactory.sol](https://github.com/optionality/clone-factory/blob/fe2ffc82f744b210dee89da9215dd6ebe2cb5b44/contracts/CloneFactory.sol).

This is the same contract as listed in [EIP-1167 - Implementation](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1167.md#implementation).

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

## Updated `clone` Bytecode Generator

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

## Old `clone` Bytecode

From [../../bytecode-annotation.txt](../../bytecode-annotation.txt):

```assembly
Init code
---------

// BK NOTE - 0x34 callvalue - wei sent together with the current call
0  | 34 <- CALLVALUE                Push the callvalue onto the stack [ callvalue ]
// BK NOTE - Comment below should be 0x42. 0x60 PUSH1 - Place 1 byte item on stack
1  | 60 <- PUSH1                    Push 0x44 the offset of the JUMPDEST given the revert label
// BK NOTE - 0x42 = 66
2  | 42 <- 0x42 `revert`            -> [ callvalue, 0x42 ]
// BK NOTE - 0x57 JUMPI - Conditionally alter the program counter
3  | 57 <- JUMPI                    Jumpi(0x42, callvalue) Jumps to `revert` if callvalue > 0 [ ]
4  | 60 <- PUSH1                    Push 0x38 the bytes length of the contract code
// BK NOTE - 0x38 = 56. Code length = 71 - 16 + 1 = 56
5  | 38 <- 0x38 `codeend-code`      -> [ 38 ]
// BK NOTE - 0x80 DUP1 Duplicate 1st stack item
6  | 80 <- DUP1                     Duplicate last stack item [ 38, 38 ]
7  | 60 <- PUSH1                    Push 0x10 the bytes which represent the offset of code start (see the 16th opcode)
// BK NOTE - 0x10 = 16
8  | 10 <- 0x10 `code`              -> [ 38, 38, 10 ]
9  | 60 <- PUSH1                    Push 0x00 onto the stack
10 | 00 <- 0x00                     -> [ 38, 38, 10, 00 ]
// BK NOTE - 0x39 CODECOPY Copy code running in current environment to memory
// BK NOTE - codecopy(t, f, s) - copy s bytes from code at position f to mem at position t
11 | 39 <- CODECOPY                 Codecopy(0x00, 0x10, 0x38) Copy 0x38 bytes of code from position 0x10 (16) to memory 0x0 -> [ 38 ]
12 | 60 <- PUSH1                    Push 0x00 onto the stack
13 | 00 <- 0xOO                     -> [ 38, 00 ]
// BK NOTE - 0xf3 RETURN Halt execution returning output data
// BK NOTE - return(p, s) - end execution, return data mem[p..(p+s))
14 | f3 <- RETURN                   Return(0x00, 0x38) [ ] Return the new code in the contract (which does not include the constructor).
// BK NOTE - 0x00 STOP - stop - stop execution, identical to return(0,0)
15 | 00 <- STOP                     Stop Call

Contract code
-------------

// BK NOTE - 0x36 CALLDATASIZE - Get size of input data in current environment. This pertains to the input data passed with the message call instruction or transaction
16 | 36 <- CALLDATASIZE             Push the calldatasize in bytes to the stack [ calldatasize ]
17 | 60 <- PUSH1                    Push 0x00 to the stack
18 | 00 <- 0x00                     -> [ calldatasize, 00 ]
19 | 60 <- PUSH1                    Push 0xFF to the stack
20 | ff <- 0xFF                     -> [ calldatasize, 00, FF ]
// BK NOTE - 0x37 CALLDATACOPY - Copy input data in current environment to memory. This pertains to the input data passed with the message call instruction or transaction
// BK NOTE - calldatacopy(t, f, s) - copy s bytes from calldata at position f to mem at position t
21 | 37 <- CALLDATACOPY             Calldatacopy(0xFF, 0x00, calldatasize) Copy `calldatasize` bytes at position 0x00 to memory at position 0xFF -> [ ]
22 | 60 <- PUSH1                    Push 0x00 to the stack
23 | 00 <- 0x00                     -> [ 00 ]
24 | 80 <- DUP1                     Duplicate last byte on stack -> [ 00, 00 ]
25 | 36 <- CALLDATASIZE             Push calldatasize to the stack -> [ 00, 00, calldatasize ]
26 | 60 <- PUSH1                    Push 0xFF to the stack
27 | ff <- 0xFF                     -> [ 00, 00, calldatasize, FF]
28 | 73 <- PUSH20                   Push 20 bytes to the stack
29 | be <- start 20 bytes
30 | ef
31 | be
32 | ef
33 | be
34 | ef
35 | be
36 | ef
37 | be
38 | ef
39 | be
40 | ef
41 | be
42 | ef
43 | be
44 | ef
45 | be
46 | ef
47 | be
48 | ef <- end 20 bytes             -> [ 00, 00, calldatasize, FF, BE, EF, ..., EF ]
// BK NOTE - 0x5a GAS - Get the amount of available gas, including the corresponding reduction for the cost of this instruction
49 | 5a <- GAS                      Push available gas to the stack -> [ 00, 00, calldatasize, FF, BE, EF, ..., EF, gas ]
// BK NOTE - 0xf4 DELEGATECALL
// BK NOTE - delegatecall(g, a, in, insize, out, outsize) - identical to callcode but also keep caller and callvalue
// BK NOTE - callcode(g, a, v, in, insize, out, outsize) - identical to call but only use the code from a and stay in the context of the current contract otherwise
// BK NOTE - call(g, a, v, in, insize, out, outsize) - call contract at address a with input mem[in..(in+insize)) providing g gas and v wei and output area mem[out..(out+outsize)) returning 0 on error (eg. out of gas) and 1 on success
50 | f4 <- DELEGATECALL             DelegateCall(gas, 0xBEEF...EF, 0xFF, calldatasize, 0x00, 0x00) Call contract at 0xBEEF...EF with input at memory location 0xFF for `calldatasize` bytes using `gas` gas. Returns 0 on error and 1 on success -> [ 0||1 ]
// BK NOTE - 0x15 ISZERO Simple not operator
51 | 15 <- ISZERO                   Checks if last item on stack is 0 and returns 1 if true -> [ 0||1, iszero ]
52 | 60 <- PUSH1                    Push the offset of revert destination based on start of the code
// BK NOTE - 0x32 = 50. 50 + 16 = 66
53 | 32 <- `revert-code`            -> [ 0||1, iszero, 32 ]
54 | 57 <- JUMPI                    JUMPI(0x32, iszero(0||1)) Jump to the revert destination if the return value is === 0 (delegatecall failed) -> [ ]
// BK NOTE - returndatasize - size of the last returndata
55 | 3d <- RETURNDATASIZE           Push `returndatasize` onto the stack -> [ returndatasize ]
56 | 80 <- DUP1                     Duplicate -> [ returndatasize, returndatasize ]
57 | 60 <- PUSH1                    Push 0x00 onto the stack
58 | 00 <- 0x00                     -> [ returndatasize, returndatasize, 00 ]
59 | 60 <- PUSH1                    Push 0xFF onto the stack
60 | ff <- 0xFF                     -> [ returndatasize, returndatasize, 00, FF ]
// BK NOTE - returndatacopy(t, f, s) - copy s bytes from returndata at position f to mem at position t
61 | 3e <- RETURNDATACOPY           Returndatacopy(0xFF, 0x00, returndatasize) Copies `returndatasize` bytes from 0x00 to memory at 0xFF -> [ returndatasize ]
62 | 60 <- PUSH1                    Push 0xFF onto the stack
63 | ff <- 0xFF                     -> [ returndatasize, FF ]
// BK NOTE - return(p, s) - end execution, return data mem[p..(p+s))
64 | f3 <- RETURN                   Return(0xFF, returndatasize) Returns the memory at location 0xFF of length `returndatasize` -> [ ]
// BK NOTE - 0x00 STOP - stop - stop execution, identical to return(0,0)
65 | 00 <- STOP                     Stop Call
66 | 5b <- JUMPDEST `revert`
67 | 60 <- PUSH1                    Push 0x00 onto the stack
68 | 00 <- 0x00                     -> [ 00 ]
69 | 80 <- DUP1                     Duplicate -> [ 00, 00 ]
// BK NOTE - REVERT = 0xfd. revert(p, s) - end execution, revert state changes, return data mem[p..(p+s))
70 | fd <- REVERT                   Revert(0x00, 0x00) -> [ ]
// BK NOTE - 0x00 STOP - stop - stop execution, identical to return(0,0)
71 | 00 <- STOP                     Stop Call
```

<br />

<hr />

## Old `clone` Bytecode Generator

From [https://github.com/optionality/clone-factory/blob/d7a76aacbf73fdd348e78ba0b750d83294bd722e/clone-contract.js](https://github.com/optionality/clone-factory/blob/d7a76aacbf73fdd348e78ba0b750d83294bd722e/clone-contract.js):

```javascript
const evm = require('@optionality.io/evm-asm');

module.exports = evm.program([

  // initialization code
  evm.callvalue(),
  evm.push1('revert'),
  evm.jumpi(),
  evm.push1('codeend-code'),
  evm.dup1(),
  evm.push1('code'),
  evm.push1(0),
  evm.codecopy(),
  evm.push1(0),
  evm.return(),
  evm.stop(),
  evm.label('code'),

  // contract code
  evm.calldatasize(),
  evm.push1(0),
  evm.push1(0xff),
  evm.calldatacopy(),
  evm.push1(0),
  evm.dup1(),
  evm.calldatasize(),
  evm.push1(0xff),
  evm.push20('0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef'),
  evm.gas(),
  evm.delegatecall(),
  evm.iszero(),
  evm.push1('revert-code'),
  evm.jumpi(),
  evm.returndatasize(),
  evm.dup1(),
  evm.push1(0x0),
  evm.push1(0xff),
  evm.returndatacopy(),
  evm.push1(0xff),
  evm.return(),
  evm.stop(),
  evm.jumpdest('revert'),
  evm.push1(0x0),
  evm.dup1(),
  evm.revert(),
  evm.stop(),

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
