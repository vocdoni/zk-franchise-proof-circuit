const path = require("path");
const fs = require("fs");
const wasm_tester = require("circom_tester").wasm;

export {};

describe("Check inputs generated from go test vectors", function () {
    this.timeout(200000);

    it("Test Census 3lvl", async () => {
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs0.json');
        let input = JSON.parse(rawdata);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census4lvl.circom"));
        // await cir.loadConstraints();
        // console.log("n_constraints", cir.constraints.length);

        const witness = await cir.calculateWitness(input, true);
    });

    it("Test Census 9lvl", async () => {
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs1.json');
        let input = JSON.parse(rawdata);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census10lvl.circom"));
        // await cir.loadConstraints();
        // console.log("n_constraints", cir.constraints.length);

        const witness = await cir.calculateWitness(input, true);
    });

    it("Test Census 19lvl", async () => {
        let rawdata = fs.readFileSync('test/go-inputs-generator/inputs2.json');
        let input = JSON.parse(rawdata);

        const cir = await wasm_tester(path.join(__dirname, "circuits", "census20lvl.circom"));
        // await cir.loadConstraints();
        // console.log("n_constraints", cir.constraints.length);

        const witness = await cir.calculateWitness(input, true);
    });
});
