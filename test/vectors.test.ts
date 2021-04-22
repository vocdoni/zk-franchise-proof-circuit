const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

const { Election, Voter } = require("../src/franchise");

export {};

describe("vectors test", function () {
    this.timeout(200000);

    it("Test Census 3lvl 1+0 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );
 
        const witness = await circuit.calculateWitness({
		censusRoot: "28834730206316395545372073374953434842705135507607839715178115559415686312490",
		censusSiblings: ["0","0","0","0"],
		privateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
		voteSigS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
		voteSigR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
		voteSigR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
		voteValue: "1",
		electionId: "10",
		nullifier: "2145560910866396686283677076353457025025099103255660157246548222611728757673",
		relayerPublicKey: "100",
		relayerProof: "13209632694830202236913773013693362233263210408804031367014084423704919780049",
		revealKey: ["0"],
		commitKey: ["14408838593220040598588012778523101864903887657864399481915450526643617223637"]
	});
        await circuit.checkConstraints(witness);
    }),

    xit("Test Census 3lvl 1+0 claims, fake-voter proof & correct revealKeys", async () => {
    });

    xit("Test Census 9lvl 1+10 claims, correct voter proof & incorrect revealKeys", async () => {
    });


    xit("Test Census 19lvl 1+50 claims, correct voter proof & incorrect revealKeys", async () => {
    });
});
