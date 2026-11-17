// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface ICanonicalRegistry {
    function game() external view returns(address);
    function contexts(bytes32) external view returns(bytes32);
    function threshold() external view returns(uint256);
    function isSigner(address) external view returns(bool);
}
interface ICanonicalTaskBinding {
    function getTaskResultBinding(bytes32) external view returns(bytes32,bytes32,uint32);
}
/// @notice Baseline: a quorum independently recomputes the ENTIRE execution.
/// It shares the authenticated task front end and identities with the dispute
/// path but uses a separate signature purpose. No audit-coverage premise or
/// challenge window is needed once a correct whole-execution certificate exists.
contract CanonicalExecutionBaseline {
    ICanonicalRegistry public immutable registry;
    bytes32 public immutable domainSeparator;
    bytes32 public constant FULL_TYPE=keccak256("FullCanonicalExecution(bytes32 taskId,bytes32 contextDigest,bytes32 traceRoot,bytes32 resultHash)");
    mapping(bytes32=>bool) public accepted;
    constructor(address registry_) {
        registry=ICanonicalRegistry(registry_);
        domainSeparator=keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("VCFHE-Full-Execution"),keccak256("1"),block.chainid,address(this)));
    }
    function accept(bytes32 taskId,bytes32 traceRoot,bytes32 resultHash,bytes[] calldata signatures) external {
        require(!accepted[taskId],"already accepted");
        bytes32 context=registry.contexts(taskId);require(context!=bytes32(0),"missing context");
        (bytes32 actualResult,bytes32 actualRoot,)=ICanonicalTaskBinding(registry.game()).getTaskResultBinding(taskId);
        require(resultHash==actualResult && traceRoot==actualRoot,"wrong task binding");
        bytes32 digest=keccak256(abi.encodePacked("\x19\x01",domainSeparator,
            keccak256(abi.encode(FULL_TYPE,taskId,context,traceRoot,resultHash))));
        address[] memory seen=new address[](signatures.length);uint256 count;
        for(uint256 i;i<signatures.length;i++) {
            bytes calldata sig=signatures[i];if(sig.length!=65)continue;
            bytes32 r;bytes32 s;uint8 v;
            assembly {r:=calldataload(sig.offset) s:=calldataload(add(sig.offset,32)) v:=byte(0,calldataload(add(sig.offset,64)))}
            if(v<27)v+=27;
            if((v!=27 && v!=28)||uint256(s)>0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)continue;
            address signer=ecrecover(digest,v,r,s);if(!registry.isSigner(signer))continue;
            bool duplicate;for(uint256 j;j<count;j++)if(seen[j]==signer)duplicate=true;
            if(!duplicate)seen[count++]=signer;
        }
        require(count>=registry.threshold(),"insufficient full recomputations");accepted[taskId]=true;
    }
}
