const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;

const { Process, Voter, computeVoteHash } = require("../src/franchise");

const { buildPoseidon } = require("circomlibjs");

export {};

describe("poseidon check", function () {
    this.timeout(100000);

    after(async () => {
        globalThis.curve_bn128.terminate();
    });


    it("poseidon check", async () => {
        const secretKey = "3876493977147089964395646989418653640709890493868463039177063670701706079087";
        const processId = [
            "115971795979716226347584900263213958763",
            "100167351390541057173626244722405453127"
        ];
        const poseidon = await buildPoseidon();
        const F = poseidon.F;

        const nullifierBytes = poseidon([secretKey, processId[0], processId[1]]);
        const nullifier = F.toObject(nullifierBytes).toString();

        const input = {
            secretKey: secretKey,
            processId: processId,
            nullifier: nullifier,
        };
        const cir = await wasm_tester(path.join(__dirname, "circuits", "poseidoncheck.circom"));
        const witness = await cir.calculateWitness(input, true);
    });
});

describe("lib test", function () {
    this.timeout(100000);

    after(async () => {
        globalThis.curve_bn128.terminate();
    });

    it("Test Census 3lvl", async () => {
        const voter = new Voter("28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f", 1);

        const proc = new Process( 1, 4);
        const pubKey = await proc.addCensus(await voter.getZkCensusKey(), voter.weight);

        const voterData = await proc.voterData(pubKey);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = await voter.vote(voterData, voteHash);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census4lvl.circom"));
        const witness = await cir.calculateWitness(input, true);
    });

    it("Test Census 9lvl", async () => {
        const voter = new Voter("28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f", 1);

        const proc = new Process(1, 10);
        const pubKey = await proc.addCensus(await voter.getZkCensusKey(), voter.weight);

        const voterData = await proc.voterData(pubKey);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = await voter.vote(voterData, voteHash);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census10lvl.circom"));
        const witness = await cir.calculateWitness(input, true);
    });


    it("Test Census 19lvl", async () => {
        const voter = new Voter("28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f", 1);

        const proc = new Process(1, 20);
        const pubKey = await proc.addCensus(await voter.getZkCensusKey(), voter.weight);

        const voterData = await proc.voterData(pubKey);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = await voter.vote(voterData, voteHash);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census20lvl.circom"));
        const witness = await cir.calculateWitness(input, true);
    });
});
