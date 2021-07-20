/*
# credential.circom

Circuit to check:
- the prover is the owner of the secret key
- zkCensusKey (hash of the user's secret key) belongs to the census
	- the secret key is inside a Hash, which is inside the Merkletree with
	  the CensusRoot (key=index), value=zkCensusKey)
- H(secretKey, electionID) == nullifier
	- to avoid proof reusability


                       +----------+
                       |          |
PUB_censusRoot+------->+          |(key)<-----+PRI_index
                       |          |
                       | SMT      |            +----------+
                       | Verifier |            |          |
PRI_siblings+--------->+          |(value)<----+ Poseidon +<-----+--+PRI_secretKey
                       |          |            |          |      |
                       +----------+            +----------+      |
                                                                 |
                                     +----------+                |
                      +----+         |          +<---------------+
PUB_nullifier+------->+ == +<--------+ Poseidon |
                      +----+         |          +<-----------+PUB_electionID
                                     +----------+
PUB_voteValue



*/

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";

template Census(nLevels) {
	signal input censusRoot;
	signal private input censusSiblings[nLevels];
	signal private input index;
	signal private input secretKey;

	signal input voteValue;

	signal input electionId;
	signal input nullifier;

	// compute zkCensusKey, which will be at the leaf
	component zkCensusKey = Poseidon(1);
	zkCensusKey.inputs[0] <== secretKey;

	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0; // 0 as is to verify inclusion
	smtClaimExists.root <== censusRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== censusSiblings[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== index;
	smtClaimExists.value <== zkCensusKey.out;

	// check nullifier
	component computedNullifier = Poseidon(2);
	computedNullifier.inputs[0] <== secretKey;
	computedNullifier.inputs[1] <== electionId;
	component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== 1;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;
}
