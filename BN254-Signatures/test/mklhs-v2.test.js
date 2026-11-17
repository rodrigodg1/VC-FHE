const { expect } = require("chai");
const { ethers } = require("hardhat");
const L = require("../scripts/mklhs-lib.js");
describe("MKLHS V2 deployment domain", function () {
  this.timeout(600000);
  it("binds chain, contract, epoch and fixed parameters; rejects a same-epoch twin replay", async () => {
    const [admin, a, b] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MKLHSVerificationV2");
    const epoch = ethers.id("test-key-epoch");
    const deploy = () => Factory.deploy("ratings", 1, 2, 0, epoch, [a.address,b.address], { value: ethers.parseEther("1") });
    const first = await deploy(); await first.waitForDeployment();
    const twin = await deploy(); await twin.waitForDeployment();
    const tag = await first.datasetTag();
    const chain = (await ethers.provider.getNetwork()).chainId;
    const derive = (chainId, address, keyEpoch) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["string","uint256","address","bytes32","bytes32","uint64","uint64","uint8"],
      ["VCFHE-LINEAR-DEPLOYMENT-V2",chainId,address,keyEpoch,awaitableParameter,1,2,0]));
    const awaitableParameter = await first.PARAMETER_DIGEST();
    expect(tag).eq(derive(chain,first.target,epoch));
    expect(tag).not.eq(derive(chain+1n,first.target,epoch));
    expect(tag).not.eq(derive(chain,first.target,ethers.id("epoch-2")));
    expect(tag).not.eq(await twin.datasetTag());
    const scenario = L.buildScenario({ n:2,op:0,tagHex:tag,seed:"v2-replay" });
    for (const contract of [first,twin]) for (const owner of scenario.owners) {
      await (await contract.connect([a,b][owner.index]).registerOwnerKey(owner.index,L.g2ToContract(owner.pk))).wait();
    }
    for (const o of scenario.owners) await (await first.admitRecord(o.index,L.g1ToContract(o.commitment),L.g1ToContract(o.signature))).wait();
    expect(await first.verifyBound(L.g1ToContract(scenario.outputCommitment))).eq(true);
    const o = scenario.owners[0];
    await expect(twin.admitRecord(0,L.g1ToContract(o.commitment),L.g1ToContract(o.signature))).revertedWithCustomError(twin,"InvalidSignature");
  });
});
