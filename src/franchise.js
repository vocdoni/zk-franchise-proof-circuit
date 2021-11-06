const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const { newMemEmptyTrie, buildPoseidon } = require("circomlibjs");
const crypto = require("crypto");

class Process {
   constructor(processId, levels) {
      this.processId = getProcessId(processId);
      this.levels = levels;
      this.tree = null;
      this.index = 0;
   }
   async addCensus(secretKeyHash) {
      if (this.tree === null) {
         this.tree = await newMemEmptyTrie();
      }
      await this.tree.insert(this.index, secretKeyHash);
      this.index++;
      return this.index-1;
   }
   async voterData(index) {
      const res = await this.tree.find(index);
      assert(res.found);
      let siblings = res.siblings;
      while (siblings.length < this.levels) siblings.push(BigInt(0));

      return {
         processId : this.processId,
         root: this.tree.root,
         siblings: siblings,
      };
   }
}

class Voter {
   constructor(secretKey) {
      this.key = { secretKey }
      this.index = 0;
   }

   async getZkCensusKey() {
      const poseidon = await buildPoseidon();
      const F = poseidon.F;
      return poseidon([this.key.secretKey]);
   }

   async vote(voterData, voteHash) {
      const poseidon = await buildPoseidon();
      const F = poseidon.F;
      const nullifierBytes = poseidon([this.key.secretKey, voterData.processId[0], voterData.processId[1]]);
      const nullifier = F.toObject(nullifierBytes).toString();


      const root = F.toObject(voterData.root).toString();
      const siblingsStr = [];
      for (let i=0;i<voterData.siblings.length;i++) {
         siblingsStr.push(voterData.siblings[i].toString());
      }
      return {
         censusRoot: root.toString(),
         censusSiblings: siblingsStr,
         index: this.index.toString(),
         secretKey : BigInt(this.key.secretKey).toString(),
         voteHash: [
            voteHash[0].toString(),
            voteHash[1].toString(),
         ],
         processId: [
            voterData.processId[0].toString(),
            voterData.processId[1].toString(),
         ],
         nullifier,
      };
   }
}

function computeVoteHash(voteBuffer) {
   const voteHashHash = crypto.createHash("sha256")
      .update(voteBuffer)
      .digest("hex");
   const voteHash = [
      BigInt("0x" + voteHashHash.slice(0, 32).match(/.{2}/g).reverse().join("")), // little-endian BigInt representation
      BigInt("0x" + voteHashHash.slice(32, 64).match(/.{2}/g).reverse().join("")) // little-endian BigInt representation
   ];
   return voteHash;
}
function getProcessId(pIdInt) {
   const pIdBuffer = Buffer.from(pIdInt.toString(), "utf-8");

   const pIdHash = crypto.createHash("sha256")
      .update(pIdBuffer)
      .digest("hex");
   const pId = [
      BigInt("0x" + pIdHash.slice(0, 32).match(/.{2}/g).reverse().join("")), // little-endian BigInt representation
      BigInt("0x" + pIdHash.slice(32, 64).match(/.{2}/g).reverse().join("")) // little-endian BigInt representation
   ];
   return pId;
}

module.exports = {
   Process,
   Voter,
   computeVoteHash
}
