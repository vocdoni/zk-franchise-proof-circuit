const path = require("path");
const tester = require("circom").tester;

export {};

const { Election, Voter, computeVoteHash } = require("../src/franchise");

describe("lib test", function () {
    this.timeout(200000);

    it("Test Census 3lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election( 1, 4);
        voter.index = await election.addCensus(voter.getZkCensusKey());

        const voterData = await election.voterData(voter.index);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = voter.vote(voterData, voteHash);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });

    it("Test Census 9lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election(1, 10);
        voter.index = await election.addCensus(voter.getZkCensusKey());

        const voterData = await election.voterData(voter.index);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = voter.vote(voterData, voteHash);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });


    it("Test Census 19lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election(1, 20);
        voter.index = await election.addCensus(voter.getZkCensusKey());

        const voterData = await election.voterData(voter.index);

        const votePreHash = Buffer.from("test", "utf-8"); // this would be the bytes of the user vote values array, or the encrypted votes
        const voteHash = computeVoteHash(votePreHash);
        let input = voter.vote(voterData, voteHash);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });
});
