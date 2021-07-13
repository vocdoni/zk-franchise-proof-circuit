const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const { smt, poseidon } = require("circomlib");

class Election {
   constructor(electionId, levels) {
      this.electionId = electionId;
      this.levels = levels;
      this.tree = null;
   }
   async addCensus(secretKeyHash) {
      if (this.tree === null) {
         this.tree = await smt.newMemEmptyTrie();
      }
      await this.tree.insert(secretKeyHash, 0);
   }
   async voterData(secretKeyHash) {
      const res = await this.tree.find(secretKeyHash);
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
   }

   getSecretKeyHash() {
      return poseidon([this.key.secretKey]);
   }

   vote(voterData, voteValue) {
      const nullifier = poseidon([this.key.secretKey, voterData.electionId]);

      return {
         censusRoot: voterData.root,
         censusSiblings: voterData.siblings,
         secretKey : BigInt(this.key.secretKey),

         voteValue,

         electionId: BigInt(voterData.electionId),
         nullifier,
      }
   }
}

module.exports = {
   Election,
   Voter
}
