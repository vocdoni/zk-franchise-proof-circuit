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
            voteSigS: "2209631892358909859397227882534860536786213289219644305743688183951383321555",
            voteSigR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            voteSigR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            voteValue: "1",
            electionId: "10",
            nullifier: "5482502190698122543507050012922267324433666089315343653961928581094977573855"
        });
        assert(circuit.checkWitness(witness));
     });
});
