const path = require("path");
const fs = require("fs");
const tester = require("circom").tester;
// const chai = require("chai");
// const assert = chai.assert;

describe("Check inputs generated from go test vectors", function () {
    this.timeout(200000);

    it("Test Census 3lvl 1+0 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );
    
        // using correct voter proof, but incorrect revealKeys
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs0.json');
        let inputs = JSON.parse(rawdata);
    
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
    
    it("Test Census 9lvl 1+10 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom")
        );
    
        // using correct voter proof, but incorrect revealKeys
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs1.json');
        let inputs = JSON.parse(rawdata);
    
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
    
    it("Test Census 19lvl 1+100 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom")
        );
    
        // using correct voter proof, but incorrect revealKeys
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs2.json');
        let inputs = JSON.parse(rawdata);
    
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

    it("Test Census 3lvl 1+0 claims, fake-voter proof & correct revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom")
        );
    
        // using incorrect voter proof, but correct revealKeys
        const witness = await circuit.calculateWitness({
            censusRoot: "0",
            censusSiblings: ["0","0","0","0"],
            privateKey: "0",
            voteSigS: "0",
            voteSigR8x: "0",
            voteSigR8y: "0",
            voteValue: "1",
            electionId: "10",
            nullifier: "0",
            relayerPublicKey: "100",
            relayerProof: "21349690342514405503176665977362532634490340702670001813783738965751319356478",
            revealKey: ["0"],
            commitKey: ["19014214495641488759237505126948346942972912379615652741039992445865937985820"]
        });
        await circuit.checkConstraints(witness);
    });
});
