// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract InheritanceParent {
    event Say(string, string);
    function inherit() virtual public pure returns(string memory) {
        return 'from Parent';
    }
}

contract InheritanceChild1 is InheritanceParent{
    function inherit() override virtual pure public returns(string memory){
        return 'child1';
    }
}

contract InheritanceChild2 is InheritanceParent{
    function inherit() override virtual public pure returns(string memory){
        return 'child2';
    }
}

contract Swc_all is InheritanceChild1, InheritanceChild2{
    // Swc-100 : function default visibility, an error in recent solidity versions
    // Remix&Solhint : 
    // Slither : 
    function _sendWinnings() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    // Swc-101 : Integer Overflow and Underflow
    // Remix&Solhint : 
    // Slither : 
    uint public count = 1;

    function run(uint256 input) public {
        count -= input;
    }
    // Swc-102 : Outdated Compiler Version
    // Remix&Solhint : 
    // Slither : Detected

    // Swc-103 : Floating Pragma
    // Remix&Solhint : 
    // Slither : Detected

    // Swc-104 : Unchecked Call Return Value
    // Remix&Solhint : Detected by compiler
    // Slither : Detected
    function callnotchecked(address callee) public {
        callee.call("");
    }
    // Swc-105 : Unprotected Ether Withdrawal
    // Remix&Solhint : 
    // Slither : 
    mapping (address => address) public owners;
    modifier onlyOwner() {
        require(owners[msg.sender] != address(0));
        _;
    }
    function newOwner(address _owner) external returns (bool) {
        require(_owner != address(0));
        owners[_owner] = msg.sender;
        return true;
    }
    function withdraw_ether() onlyOwner public {
        payable(msg.sender).transfer(address(this).balance);
    }
    // Swc-106 : Unprotected SELFDESTRUCT Instruction
    // Remix&Solhint : Detected
    // Slither : Detected
    function suicideAnyone() external{
        selfdestruct(payable(msg.sender));
    }
    // Swc-107 : Reentrancy
    // Remix&Solhint : Detected
    // Slither : Detected
    mapping(address => uint256) public balances;
    function withdraw() public {
        require(
            balances[msg.sender] >= 1 ether,
            "Insufficient funds.  Cannot withdraw"
        );
        uint256 bal = balances[msg.sender];
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to withdraw sender's balance");
        balances[msg.sender] = 0;
    }
    // Swc-108 : State Variable Default Visibility
    // Remix&Solhint : Detected
    // Slither : 
    uint storeduint1 = 15;
    uint constant constuint = 16;
    uint32 investmentsDeadlineTimeStamp = uint32(block.timestamp); 
    // Swc-109 : Uninitialized Storage Pointer, an error in recent solidity versions
    // Remix&Solhint : 
    // Slither : Detected
    struct Game {
        address player;
        uint256 number;
    }
    function play(uint256 number) payable public {
        Game memory game;
        game.number = number;
        game.player = msg.sender;
    }
    // Swc-110 : Assert Violation
    // Remix&Solhint : Detected Use
    // Slither : Detected tautology
    int param = -10;
    function assertion() public view{
        assert(param>0);
        assert(balances[msg.sender]<0);
        assert(false);
    }
    // Swc-111 : Use of Deprecated Solidity Functions, an error in recent solidity versions
    // Remix&Solhint : 
    // Slither : 
    function deprecated() public {
        /*uint gas = msg.gas;
        bytes32 blockhash_ = block.blockhash(0);
        bytes32 hashofhash = sha3(blockhash_);
        suicide(address(0));
        address(this).callcode();
        var a = [1,2,3];*/
    }
    // Swc-112 : Delegatecall to Untrusted Callee
    // Remix&Solhint : Detected
    // Slither : Detected
    function delegating(address address_) payable public{
        (bool success ,)= address_.delegatecall(msg.data);
        require(success);
    }
    // Swc-113 : DoS with Failed Call
    // Remix&Solhint : 
    // Slither : 
    address public currentLeader;
    uint public highestBid = 0;
    function bid() payable public{
        require(msg.value > highestBid);
        require(payable(currentLeader).send(highestBid));

        currentLeader = msg.sender;
        highestBid = msg.value;
    }
    // Swc-114 : Transaction Order Dependence
    // Remix&Solhint : 
    // Slither : 
    bool public claimed;
    uint public reward;
    address public owner;
    function setReward() public payable {
        require (!claimed);

        require(msg.sender == owner);
        payable(owner).transfer(reward);
        reward = msg.value;
    }
    function claimReward(uint256 submission) public {
        require (!claimed);
        require(submission < 10);

        payable(msg.sender).transfer(reward);
        claimed = true;
    }
    // Swc-115 : Authorization through tx.origin
    // Remix&Solhint : Detected
    // Slither : Detected
    function transfer(address payable _to, uint _amount) public {
        require(tx.origin == owner, "Not owner");
        (bool sent, ) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }
    // Swc-116 : Block values as a proxy for time
    // Remix&Solhint : Detected
    // Slither : Detected
    struct User {
        uint amount;
        uint unlockBlock; 
    }
    mapping(address => User) public users;
    function lockEth(uint _time, uint _amount) public payable {
        require(msg.value == _amount, 'must send exact amount');
        users[msg.sender].unlockBlock = block.timestamp + _time;
        users[msg.sender].amount = _amount;
    }
    // Swc-117 : Signature Malleability
    // Remix&Solhint : 
    // Slither : 
    mapping(bytes32 => bool) signatureUsed;
    function transfer( bytes memory _signature, address _to, uint256 _value, uint256 _gasPrice, uint256 _nonce) public {
      bytes32 txid = keccak256(abi.encodePacked(getTransferHash(_to, _value, _gasPrice, _nonce), _signature));
      require(!signatureUsed[txid]);
      address from = recoverTransferPreSigned(_signature, _to, _value, _gasPrice, _nonce);
      require(balances[from] > _value);
      balances[from] -= _value;
      balances[_to] += _value;
      signatureUsed[txid] = true;
    }
    function recoverTransferPreSigned(bytes memory _sig, address _to, uint256 _value, uint256 _gasPrice, uint256 _nonce) public view returns (address recovered) {
        return ecrecoverFromSig(getSignHash(getTransferHash(_to, _value, _gasPrice, _nonce)), _sig);
    }
    function getTransferHash( address _to, uint256 _value, uint256 _gasPrice, uint256 _nonce) public view returns (bytes32 txHash) {
        return keccak256(abi.encodePacked(address(this), bytes4(0x1296830d), _to, _value, _gasPrice, _nonce));
    }
    function getSignHash(bytes32 _hash) public pure returns (bytes32 signHash) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
    }
    function ecrecoverFromSig(bytes32 hash, bytes memory sig) public pure returns (address recoveredAddress) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (sig.length != 65) return address(0);
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) {
          v += 27;
        }
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
    // Swc-118 : Incorrect Constructor Name
    // Remix&Solhint : 
    // Slither : 
    function swc_all() public{
        owner = msg.sender;
    }
    // Swc-119 : Shadowing State Variables
    // Remix&Solhint : Detected by compiler
    // Slither : Detected
    uint n = 2;
    function test1() public pure returns (uint n) {
        return n;
    }
    function test2() public pure returns (uint n) {
        n = 1;
        return n;
    }
    // Swc-120 : Weak Sources of Randomness from Chain Attributes
    // Remix&Solhint : Almost Detected
    // Slither : 
    bytes32 answer;
    function GuessTheRandomNumberChallenge() public payable {
        require(msg.value == 1 ether);
        answer = keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp));
    }
    //######### Swc-121 : Missing Protection against Signature Replay Attacks
    //######### Swc-122 : Lack of Proper Signature Verification
    // Swc-123 : Requirement Violation
    // Remix&Solhint : 
    // Slither : 
    function baz(int256 x) public pure returns (int256) {
        require(x > 0);
        return 42;
    }
    // Swc-124 : Write to Arbitrary Storage Location, smart contract no longer vunlnerable, can't resize array with array.length
    // Remix&Solhint : 
    // Slither : 
    uint[] private bonusCodes;
    function PopBonusCode() public view{
        require(0 <= bonusCodes.length);
        //bonusCodes.length--;
    }
    function UpdateBonusCodeAt(uint idx, uint c) public {
        require(idx < bonusCodes.length);
        bonusCodes[idx] = c;
    }
    // Swc-125 : Incorrect Inheritance Order
    // Remix&Solhint : 
    // Slither : 
    function inherit() override(InheritanceChild1, InheritanceChild2) public pure returns(string memory){
        return "something";
    }
    // Swc-126 : Insufficient Gas Griefing
    // Remix&Solhint : 
    // Slither : 
    uint public transactionId;
    struct Tx {
        bytes data;
        bool executed;
    }
    mapping (uint => Tx) transactions;
    function relay(Swc126_Target target, bytes memory _data) public returns(bool) {
        require(transactions[transactionId].executed == false, 'same transaction twice');
        transactions[transactionId].data = _data;
        transactions[transactionId].executed = true;
        transactionId += 1;
        (bool success, ) = address(target).call(abi.encodeWithSignature("execute(bytes)", _data));
        return success;
    }
    // Swc-127 : Arbitrary Jump with Function Type Variable
    // Remix&Solhint : Detected assembly
    // Slither : Detected assembly
    function frwd() internal
        { withdraw(); }
    struct Func { function () internal f; }  
    function breakIt(uint parameter) public payable {
        require(msg.value != 0, 'send funds!');
        Func memory func;
        func.f = frwd;
        assembly { mstore(func, add(mload(func), parameter)) }
        func.f();
    }
    // Swc-128 : DoS With Block Gas Limit
    // Remix&Solhint : 
    // Slither : 
    address[] listAddresses;
    function ifillArray() public returns (bool){
        if(listAddresses.length<1500) {

            for(uint i=0;i<350;i++) {
                listAddresses.push(msg.sender);
            }
            return true;

        } else {
            listAddresses = new address[](0);
            return false;
        }
    }
    // Swc-129 : Typographical Error, an error in recent solidity versions
    // Remix&Solhint : 
    // Slither : 
    uint public numberOne = 1;
    function alwaysOne() public {
        //numberOne =+ 1;
    }
    // Swc-130 : Right-To-Left-Override control character (U+202E), an error in recent solidity versions
    // Swc-131 : Presence of unused variables
    // Remix&Solhint : 
    // Slither : Detected
    int internal j = 500;
    // Swc-132 : Unexpected Ether balance
    // Remix&Solhint : 
    // Slither : Detected
    function lock() external payable{
        require(address(this).balance == msg.value,"where the hell did the money come from");
    }
    // Swc-133 : Hash Collisions With Multiple Variable Length Arguments
    // Remix&Solhint : 
    // Slither : Detected
    mapping(address => bool) public isAdmin;
    mapping(address => bool) public isRegularUser;
    constructor(){
        isAdmin[msg.sender] = true;
    }
    function addUsers( address[] calldata admins, address[] calldata regularUsers, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash_ = keccak256(abi.encodePacked(admins, regularUsers));
        if (!isAdmin[msg.sender]) {            
            address signer = ecrecover(hash_,v,r,s);
            require(isAdmin[signer], "Only admins can add users.");
        }
        for (uint256 i = 0; i < admins.length; i++) {
            isAdmin[admins[i]] = true;
        }
        for (uint256 i = 0; i < regularUsers.length; i++) {
            isRegularUser[regularUsers[i]] = true;
        }
    }
    // Swc-134 : Message call with hardcoded gas amount
    // Remix&Solhint : Detected use of send
    // Slither : Detected law level calls
    address payable _callable = payable(0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa);
    ICallable callable = ICallable(_callable);
    function doSend(uint256 amount) public {
        _callable.transfer(amount);
    }
    // Swc-135 : Code With No Effects
    // Remix&Solhint : Detected == not used
    // Slither : 
    function deposit(uint amount) public payable {
        require(msg.value == amount, 'incorrect amount');
        balances[msg.sender] == amount;
        msg.sender.call{value: amount};
    }
    // Swc-136 : Unencrypted Private Data On-Chain
    // Remix&Solhint : 
    // Slither : 
    struct Player {
        address addr;
        uint number;
    }

    Player[2] private players;
}

interface ICallable {
    function callMe() external;
}

contract Swc126_Target {
    event Log(string message, uint data);
    uint public sum = 1;

    function execute(bytes memory _data) public {
        //require(gasleft()>=gaslimit)
        for (uint i=0; i<10; i++){
            sum += i;
        }
    }
}