pragma circom 2.1.0;

/*
Circuit to check:
- the prover is the owner of the private key
- keyHash (hash of the user's public key) belongs to the census
		- the public key is generated based on the provided private key
		- the public key is inside a hash, which is inside the Merkletree with 
		the CensusRoot and siblings (key=keyHash, value=weight)
- H(private key, processID) == nullifier
	- to avoid proof reusability

			    	+----------+
				|          |
	PUB_censusRoot+-------->+          |(value)<-----+PUB_weight
				|          |
				| SMT      |         +----------+    +------------+
				| Verifier |         |          |    |            |
	PRI_siblings+---------->+          |(key)<---+ Poseidon +<---+ publickKey +-+---+PRI_privateKey
				|          |         |          |    |            | |
				+----------+         +----------+    +------------+ |
	       									    |
						+----------+			    |
				+----+		|          +<-----------------------+
	PUB_nullifier+--------->+ == +<---------+ Poseidon |<------------+PUB_processID_0
				+----+		|          +<------------+PUB_processID_1
						+----------+
	PUB_voteHash†
*/

include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/smt/smtverifier.circom";


function truncate(in, n) {
    var pos = 10**n;
    var partial = in - (in % pos);
    var res = partial / pos;
    return res;
}

function length(in) {
    var iter = in;
    var len = 0;
    while (iter > 0) {
        len++;
        iter = truncate(iter, 1);
    }
    return len;
}

template Census(nLevels) {
	var realNLevels = nLevels+1;
	// defined by the process
	signal input processId[2]; // public
	signal input censusRoot; // public

	// defined by the user
	signal input nullifier; // public
	signal input weight; // public
	// voteHash is not operated inside the circuit, assuming that in
	// Circom an input that is not used will be included in the constraints
	// system and in the witness
	signal input voteHash[2]; // public

	// private signals
	signal input censusSiblings[realNLevels];
	signal input privateKey;
	signal input shifted;

	// compute publicKey
	component babyPbk = BabyPbk();
	babyPbk.in <== privateKey;

	// compute keyHash, which will be at the leaf
	component keyHash = Poseidon(2);
	keyHash.inputs[0] <== babyPbk.Ax;
	keyHash.inputs[1] <== babyPbk.Ay;

	var pubKey = keyHash.out;
	var tPubKey = truncate(pubKey, shifted);

	// check the Merkletree with CensusRoot, siblings, keyHash and weight
	component smtClaimExists = SMTVerifier(realNLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0; // 0 as is to verify inclusion
	smtClaimExists.root <== censusRoot;
	for (var i=0; i<realNLevels; i++) {
		smtClaimExists.siblings[i] <== censusSiblings[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <-- tPubKey;
	smtClaimExists.value <== weight;

	// check nullifier (electionID + privateKey)
	component computedNullifier = Poseidon(3);
	computedNullifier.inputs[0] <== privateKey;
	computedNullifier.inputs[1] <== processId[0];
	computedNullifier.inputs[2] <== processId[1];
	component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== 1;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;
}
