const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("Census test", function () {
    this.timeout(200000);


    it("Test Census", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "census.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        const witness = circuit.calculateWitness({
            censusRoot: "19320996555686578340721123783667964122950395043947431390465231639709386066161",
            censusSiblings: ["0", "0", "0", "0"],
            privateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            voteSigS: "0",
            voteSigR8x: "0",
            voteSigR8y: "0",
            voteValue: "0",
            electionId: "0",
            nullifier: "0",
        });
        assert(circuit.checkWitness(witness));
     });
});
