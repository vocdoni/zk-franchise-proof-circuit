/*
# credential.circom

Circuit to check:
- the prover is the owner of the secret key
- the prover belongs to the census
	- the secret key is inside a Hash, which is inside the Merkletree with the CensusRoot (key=Poseidon([secretKey]), value=0)
- H(secretKey, electionID) == nullifier
	- to avoid proof reusability


                       +----------+         +----------+
                       |          |         |          |
                       |          +<--------+ Poseidon +<-----+--+PRI_secretKey
PUB_censusRoot+------->+ SMT      |         |          |      |
                       | Verifier |         +----------+      |
PRI_siblings+--------->+          |                           |
                       |          |                           |
                       +----------+                           |
                                         +----------+         |
                          +----+         |          +<--------+
    PUB_nullifier+------->+ == +<--------+ Poseidon |
                          +----+         |          +<-----------+PUB_electionID
                                         +----------+


*/

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

template Census(nLevels) {
	signal input censusRoot;
	signal private input censusSiblings[nLevels];
	signal private input secretKey;

	signal input voteValue;

	signal input electionId;
	signal input nullifier;

	// compute secretKeyHash, which will be at the leaf
	component secretKeyHash = Poseidon(1);
	secretKeyHash.inputs[0] <== secretKey;

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
	smtClaimExists.key <== secretKeyHash.out;
	smtClaimExists.value <== 0;

	// check nullifier
	component computedNullifier = Poseidon(2);
	computedNullifier.inputs[0] <== secretKey;
	computedNullifier.inputs[1] <== electionId;
	component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== 1;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;
}
