const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const { smt, poseidon } = require("circomlib");
const crypto = require("crypto");

class Election {
   constructor(electionId, levels) {
      this.electionId = electionId;
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
         electionId : this.electionId,
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

   vote(voterData, voteValue) {
      const nullifier = poseidon([this.key.secretKey, voterData.electionId]);

      return {
         censusRoot: voterData.root,
         censusSiblings: voterData.siblings,
         index: this.index,
         secretKey : BigInt(this.key.secretKey),

         voteValue,

         electionId: BigInt(voterData.electionId),
         nullifier,
      }
   }
}

function computeVoteValue(voteBuffer) {
   const voteValueHash = crypto.createHash("sha256")
      .update(voteBuffer)
      .digest("hex");
   const voteValue = [
      BigInt("0x" + voteValueHash.slice(0, 32).match(/.{2}/g).reverse().join("")), // little-endian BigInt representation
      BigInt("0x" + voteValueHash.slice(32, 64).match(/.{2}/g).reverse().join("")) // little-endian BigInt representation
   ];
   return voteValue;
}

module.exports = {
   Election,
   Voter,
   computeVoteValue
}
