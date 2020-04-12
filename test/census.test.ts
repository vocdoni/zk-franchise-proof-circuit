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
            // TODO
        });
        assert(circuit.checkWitness(witness));
     });
});
