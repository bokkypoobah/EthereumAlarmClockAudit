# DelayedPayment

Source file [../../../contracts/_examples/DelayedPayment.sol](../../../contracts/_examples/DelayedPayment.sol).

<br />

<hr />

```solidity
// BK Ok
pragma solidity 0.4.24;

// BK Ok
import "contracts/Interface/SchedulerInterface.sol";

/// Example of using the Scheduler from a smart contract to delay a payment.
// BK Ok
contract DelayedPayment {

    // BK Ok
    SchedulerInterface public scheduler;
    
    // BK Next 3 Ok
    address recipient;
    address owner;
    address public payment;

    // BK Next 3 Ok
    uint lockedUntil;
    uint value;
    uint twentyGwei = 20000000000 wei;

    // BK Ok
    constructor(
        address _scheduler,
        uint    _numBlocks,
        address _recipient,
        uint _value
    )  public payable {
        // BK Next 3 Ok
        scheduler = SchedulerInterface(_scheduler);
        lockedUntil = block.number + _numBlocks;
        recipient = _recipient;
        owner = msg.sender;
        value = _value;

        uint endowment = scheduler.computeEndowment(
            twentyGwei,
            twentyGwei,
            200000,
            0,
            twentyGwei
        );

        // BK Ok
        payment = scheduler.schedule.value(endowment)( // 0.1 ether is to pay for gas, bounty and fee
            this,                   // send to self
            "",                     // and trigger fallback function
            [
                200000,             // The amount of gas to be sent with the transaction.
                0,                  // The amount of wei to be sent.
                255,                // The size of the execution window.
                lockedUntil,        // The start of the execution window.
                twentyGwei,    // The gasprice for the transaction (aka 20 gwei)
                twentyGwei,    // The fee included in the transaction.
                twentyGwei,         // The bounty that awards the executor of the transaction.
                twentyGwei * 2     // The required amount of wei the claimer must send as deposit.
            ]
        );

        assert(address(this).balance >= value);
    }

    // BK Ok
    function () public payable {
        // BK Ok
        if (msg.value > 0) { //this handles recieving remaining funds sent while scheduling (0.1 ether)
            // BK Ok
            return;
        // BK Ok
        } else if (address(this).balance > 0) {
            // BK Ok
            payout();
        // BK Ok
        } else {
            // BK Ok
            revert();
        }
    }

    // BK Ok
    // BK NOTE - If the ETH deposited in this contract >= 2 x value, the integer multiple excess over the value can be sent
    // BK NOTE - to the recipient, and this can be called by anyone once the lockedUntil time is passed  
    function payout()
        public returns (bool)
    {
        // BK Ok
        require(block.number >= lockedUntil);
        
        // BK Ok
        recipient.transfer(value);
        // BK Ok
        return true;
    }

    // BK Ok - Anyone can execute whenever, but only the owner gets the balance
    // BK NOTE - This can be called by anyone anytime and will send the ETH back to the owner, causing the future scheduled payments to fail
    function collectRemaining()
        public returns (bool) 
    {
    	// BK Ok
        owner.transfer(address(this).balance);
    }
}
```
