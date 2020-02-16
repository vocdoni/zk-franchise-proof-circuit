const bigInt = require("../node_modules/snarkjs").bigInt;
const { assert } = require("chai");
const createBlakeHash = require("blake-hash");
const { babyJub, eddsa, smt, poseidon } = require("../za/interop/circuits/circomlib");

const hash = poseidon.createHash(6, 8, 57);

function genKeyPair(rawpvkHex) {
    const rawpvk = Buffer.from(rawpvkHex, "hex");
    const rawpvkHash = eddsa.pruneBuffer(createBlakeHash("blake512").update(rawpvk).digest().slice(0, 32));
    const pvk = bigInt.leBuff2int(rawpvkHash).shr(3);
    const A = babyJub.mulPointEscalar(babyJub.Base8, pvk);
    return { rawpvk , pvk , pbk : { x: A[0], y: A[1] } }
}

class FPCensus {
    constructor(levels, authorities) {
        this.levels = levels;
        this.tree = null;
        this.authorities = []
        for (let n=0;n<authorities;n++) {
            const raw = "000000000000000000000000000000000000000000000000000000000000000"+n;
            this.authorities.push(genKeyPair(raw));           
        }
    }
    async add(idx, publicKeyHash) {
        if (this.tree === null) {
            this.tree = await smt.newMemEmptyTrie();
        }
        await this.tree.insert(idx, publicKeyHash);
    }
    async proofOfInclusion(idx) {
        const res = await this.tree.find(idx);
        assert(res.found);
        let siblings = res.siblings;
        while (siblings.length < this.levels) siblings.push(bigInt(0));
        
        let commitments = [];
        for (let n=0;n<this.authorities.length;n++) {
            commitments.push(this.authorities[n].pbk.x);
        }

        return {
            root: this.tree.root,
            siblings: siblings,
            commitments : commitments,

        };
    }
}

class FPVoter {
    constructor(idx, rawpvkHex) {
        this.idx = idx;
        this.key = genKeyPair(rawpvkHex);
    }

    async getPublicKeyHash() {
        return hash([this.key.pbk.x, this.key.pbk.y]);
    }

    async getInput(votingId, voteValue, proofOfInclusion) {

        const nullifier = hash([this.key.pvk, votingId]);
        const signature = eddsa.signPoseidon(this.key.rawpvk, voteValue);

        let globalNullifiers = []
        for (let n=0;n<proofOfInclusion.commitments.length;n++) {
            globalNullifiers.push(0);
        }

        return {
            privateKey : this.key.pvk,
            votingId,
            nullifier,
            censusRoot: proofOfInclusion.root,
            censusSiblings: proofOfInclusion.siblings,
            censusIdx: this.idx,
            voteSigS: signature.S,
            voteSigR8x: signature.R8[0],
            voteSigR8y: signature.R8[1],
            voteValue,
            gcommitment : proofOfInclusion.commitments,
            gnullifier  : globalNullifiers,
        }
    }
}

module.exports = {
    FPCensus,
    FPVoter
}
