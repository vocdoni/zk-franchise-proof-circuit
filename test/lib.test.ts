const path = require("path");
const tester = require("circom").tester;

export {};

const { Election, Voter } = require("../src/franchise");

describe("lib test", function () {
    this.timeout(200000);

    it("Test Census 3lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election(/* electionid */ 1, /* levels */ 4);
        await election.addCensus(voter.getSecretKeyHash());

        const voterData = await election.voterData(voter.getSecretKeyHash());
        const voteValue = BigInt(2);
        let input = voter.vote(voterData, voteValue);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    }),

    it("Test Census 9lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election(/* electionid */ 1, /* levels */ 10);
        await election.addCensus(voter.getSecretKeyHash());

        const voterData = await election.voterData(voter.getSecretKeyHash());
        const voteValue = BigInt(2);
        let input = voter.vote(voterData, voteValue);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });


    it("Test Census 19lvl", async () => {
        const voter = new Voter("3876493977147089964395646989418653640709890493868463039177063670701706079087");

        const election = new Election(/* electionid */ 1, /* levels */ 20);
        await election.addCensus(voter.getSecretKeyHash());

        const voterData = await election.voterData(voter.getSecretKeyHash());
        const voteValue = BigInt(2);
        let input = voter.vote(voterData, voteValue);

        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(input);
        await circuit.checkConstraints(witness);
    });
});
