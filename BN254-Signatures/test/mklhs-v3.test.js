const { expect } = require("chai");
const { ethers } = require("hardhat");
const L = require("../scripts/mklhs-lib.js");
describe("Public-input linear profile separation", function () {
  this.timeout(600000);
  it("rejects legacy parameter and twin-deployment signatures", async () => {
    const [,a,b]=await ethers.getSigners(),epoch=ethers.id("public-input-epoch");
    const make=async name=>{const f=await ethers.getContractFactory(name);
      const c=await f.deploy("ratings",1,2,0,epoch,[a.address,b.address],{value:ethers.parseEther("1")});await c.waitForDeployment();return c;};
    const old=await make("MKLHSVerificationV2"),current=await make("MKLHSVerificationV3"),twin=await make("MKLHSVerificationV3");
    expect(await old.PARAMETER_DIGEST()).not.eq(await current.PARAMETER_DIGEST());
    const {PUBLIC_LINEAR_PARAMETERS}=await import("../scripts/linear-output-policy.mjs");
    expect(await current.PARAMETER_DIGEST()).eq(ethers.id(PUBLIC_LINEAR_PARAMETERS));
    const scenario=L.buildScenario({n:2,op:0,tagHex:await current.datasetTag(),seed:"public-profile-regression"});
    for(const c of [old,current,twin])for(const owner of scenario.owners)
      await(await c.connect([a,b][owner.index]).registerOwnerKey(owner.index,L.g2ToContract(owner.pk))).wait();
    for(const owner of scenario.owners){
      const args=[owner.index,L.g1ToContract(owner.commitment),L.g1ToContract(owner.signature)];
      await(await current.admitRecord(...args)).wait();
      await expect(old.admitRecord(...args)).revertedWithCustomError(old,"InvalidSignature");
      await expect(twin.admitRecord(...args)).revertedWithCustomError(twin,"InvalidSignature");
    }
    expect(await current.verifyBound(L.g1ToContract(scenario.outputCommitment))).eq(true);
  });
});
