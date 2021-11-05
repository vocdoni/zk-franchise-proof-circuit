const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const { smt, poseidon } = require("circomlib");
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
         this.tree = await smt.newMemEmptyTrie();
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

   getZkCensusKey() {
      return poseidon([this.key.secretKey]);
   }

   vote(voterData, voteHash) {
      const nullifier = poseidon([this.key.secretKey, voterData.processId[0], voterData.processId[1]]);

      return {
         censusRoot: voterData.root,
         censusSiblings: voterData.siblings,
         index: this.index,
         secretKey : BigInt(this.key.secretKey),

         voteHash,

         processId: voterData.processId,
         nullifier,
      }
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
