const bigInt = require("snarkjs").bigInt;
const { assert } = require("chai");
const createBlakeHash = require("blake-hash");
const { babyJub, eddsa, smt, poseidon } = require("circomlib");
const ffutils = require("ffjavascript").utils;
const Scalar = require("ffjavascript").Scalar;
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

class Election {
    constructor(electionId, levels, authorities) {
        this.electionId = electionId;
	this.levels = levels;
        this.tree = null;
	this.commitKey = []
        this.revealKey = []
        for (let n=0;n<authorities;n++) {
            const raw = BigInt(1+n);
            this.revealKey.push(raw);
	    this.commitKey.push(poseidon([raw]));
        }
    }
    async addCensus(publicKeyHash) {
        if (this.tree === null) {
            this.tree = await smt.newMemEmptyTrie();
        }
        await this.tree.insert(publicKeyHash, 0);
    }
    async voterData(publicKeyHash) {
        const res = await this.tree.find(publicKeyHash);
        assert(res.found);
        let siblings = res.siblings;
        while (siblings.length < this.levels) siblings.push(BigInt(0));
        
        return {
	    electionId : this.electionId,
            root: this.tree.root,
            siblings: siblings,
            commitKey : this.commitKey,
        };
    }
}

class Voter {
    constructor(rawpvkHex) {
       const rawpvk = Buffer.from(rawpvkHex, "hex");
       const rawpvkHash = eddsa.pruneBuffer(createBlakeHash("blake512").update(rawpvk).digest().slice(0, 32));
       const pvk = Scalar.shr(ffutils.leBuff2int(rawpvkHash),3);
       const A = babyJub.mulPointEscalar(babyJub.Base8, pvk);
       this.key = { rawpvk , pvk , pbk : { x: A[0], y: A[1] } }
   }

    getPublicKeyHash() {
        return poseidon([this.key.pbk.x, this.key.pbk.y]);
    }

    vote(voterData, voteValue, relayerPublicKey) {
        const nullifier = poseidon([this.key.pvk, voterData.electionId]);
        const signature = eddsa.signPoseidon(this.key.rawpvk, voteValue);
	const relayerProof = poseidon([nullifier, relayerPublicKey])

	let revealKey = [] 
        for (let n=0;n<voterData.commitKey.length;n++) {
            revealKey.push(BigInt(0));
        }

        return {
            censusRoot: voterData.root,
            censusSiblings: voterData.siblings,
	    privateKey : this.key.pvk,

            voteSigS: signature.S,
            voteSigR8x: signature.R8[0],
            voteSigR8y: signature.R8[1],
 
            voteValue,

	    electionId: BigInt(voterData.electionId),
            nullifier,
           
            relayerPublicKey,
	    relayerProof,

	    revealKey,
	    commitKey : voterData.commitKey
        }
    }
}

module.exports = {
    Election,
    Voter
}
