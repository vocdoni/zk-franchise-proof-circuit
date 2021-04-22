const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

const { Election, Voter } = require("../src/franchise");

export {};

describe("lib test", function () {
    this.timeout(200000);

    it("Test Census 3lvl 1+0 claims, correct voter proof & incorrect revealKeys", async () => {
       const voter = new Voter("0001020304050607080900010203040506070809000102030405060708090021");
      
        const election = new Election(/* electionid */ 1, /* levels */ 4, /* authorities */ 1);
        await election.addCensus(voter.getPublicKeyHash());

        const voterData = await election.voterData(voter.getPublicKeyHash());
        const voteValue = BigInt(2);
        const relayerPublicKey = BigInt(1); 
	let input = voter.vote(voterData, voteValue, relayerPublicKey);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );
 
        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    }),

    it("Test Census 3lvl 1+0 claims, fake-voter proof & correct revealKeys", async () => {
        const voter = new Voter("0001020304050607080900010203040506070809000102030405060708090021");
      
        const election = new Election(/* electionid */ 1, /* levels */ 4, /* authorities */ 1);
        await election.addCensus(voter.getPublicKeyHash());

        const voterData = await election.voterData(voter.getPublicKeyHash());
        const voteValue = BigInt(2);
        const relayerPublicKey = BigInt(1); 
	let input = voter.vote(voterData, voteValue, relayerPublicKey);
	input.voteSigS++;
	input.revealKey = election.revealKey;

        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );
 
        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });

    it("Test Census 9lvl 1+10 claims, correct voter proof & incorrect revealKeys", async () => {
        const voter = new Voter("0001020304050607080900010203040506070809000102030405060708090021");
      
        const election = new Election(/* electionid */ 1, /* levels */ 10, /* authorities */ 10);
        await election.addCensus(voter.getPublicKeyHash());

        const voterData = await election.voterData(voter.getPublicKeyHash());
        const voteValue = BigInt(2);
        const relayerPublicKey = BigInt(1); 
	let input = voter.vote(voterData, voteValue, relayerPublicKey);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom"),
            {reduceConstraints: false}
        );
 
        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });


    it("Test Census 19lvl 1+50 claims, correct voter proof & incorrect revealKeys", async () => {
        const voter = new Voter("0001020304050607080900010203040506070809000102030405060708090021");
      
        const election = new Election(/* electionid */ 1, /* levels */ 20, /* authorities */ 50);
        await election.addCensus(voter.getPublicKeyHash());

        const voterData = await election.voterData(voter.getPublicKeyHash());
        const voteValue = BigInt(2);
        const relayerPublicKey = BigInt(1); 
	let input = voter.vote(voterData, voteValue, relayerPublicKey);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom"),
            {reduceConstraints: false}
        );
 
        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });
});
