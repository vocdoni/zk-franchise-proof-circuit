pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonCheck() {
	signal input secretKey;
	signal input processId[2];
	signal input nullifier;

	component computedNullifier = Poseidon(3);
	computedNullifier.inputs[0] <== secretKey;
	computedNullifier.inputs[1] <== processId[0];
	computedNullifier.inputs[2] <== processId[1];
	component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== 1;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;
}

component main = PoseidonCheck();
