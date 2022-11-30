const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const { newMemEmptyTrie, buildPoseidon, buildEddsa, buildBabyjub } = require("circomlibjs");
const crypto = require("crypto");
const createBlakeHash = require("blake-hash");
const Scalar = require("ffjavascript").Scalar;
const ffutils = require("ffjavascript").utils;


class Process {
   constructor(processId, levels) {
      this.processId = getProcessId(processId);
      this.levels = levels+1;
      this.tree = null;
   }
   async addCensus(publicKey, weight) {
      if (this.tree === null) {
         this.tree = await newMemEmptyTrie();
      }
      await this.tree.insert(publicKey, weight);
      return publicKey;
   }
   async voterData(publicKey) {
      const res = await this.tree.find(publicKey);
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
   constructor(rawPrivateKey, weight) {
      this.key = { rawPrivateKey }
      this.weight = weight;
   }

   async getZkCensusKey() {
      const eddsa = await buildEddsa();
      const poseidon = await buildPoseidon();
      const babyJub = await buildBabyjub();
      
      const rawPrivateKeyBuffer = Buffer.from(this.key.rawPrivateKey, "hex");
      const rawPrivateKeyHash = eddsa.pruneBuffer(createBlakeHash("blake512").update(rawPrivateKeyBuffer).digest().slice(0, 32));
      
      this.key.privateKey = Scalar.shr(ffutils.leBuff2int(rawPrivateKeyHash), 3);
      const A = babyJub.mulPointEscalar(babyJub.Base8, this.key.privateKey);

      this.key.publicKey = { x: A[0], y: A[1] }

      return poseidon([this.key.publicKey.x, this.key.publicKey.y]);
   }

   async vote(voterData, voteHash) {
      const poseidon = await buildPoseidon();
      const F = poseidon.F;
      const nullifierBytes = poseidon([this.key.privateKey, voterData.processId[0], voterData.processId[1]]);
      const nullifier = F.toObject(nullifierBytes).toString();

      const root = F.toObject(voterData.root).toString();
      const siblingsStr = [];
      for (let i=0;i<voterData.siblings.length;i++) {
         siblingsStr.push(voterData.siblings[i].toString());
      }

      return {
         censusRoot: root.toString(),
         censusSiblings: siblingsStr,
         weight: this.weight.toString(),
         privateKey : this.key.privateKey,
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
