const path = require("path");
const fs = require("fs");
const tester = require("circom").tester;

export {};

describe("Check inputs generated from go test vectors", function () {
    this.timeout(200000);

    it("Test Census 3lvl", async () => {
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

    it("Test Census 9lvl", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom")
        );

        // using correct voter proof, but incorrect revealKeys
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs1.json');
        let inputs = JSON.parse(rawdata);

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

    it("Test Census 19lvl", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom")
        );

        // using correct voter proof, but incorrect revealKeys
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs2.json');
        let inputs = JSON.parse(rawdata);

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
});
