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

// ZkAddress reduces the provided poseidon hash of a babyJubJub publicKey 
// to the default size of the Vochain Address (20 bytes), getting its first 
// 8*bytes bits.
template ZkAddress() {
    signal input keyHash;
    signal output address;
    // Get the binary representation of the input
    component n2b = Num2Bits_strict();
    n2b.in <== keyHash; 
	// Define the number of bits that fit into the default Vochain Address size
	var vochainAddrBits = 160; // (20 bytes * 8 bits/byte)
	// Get the binary representation of the hash of the public key that 
	// completes the address size
    var addrBits[vochainAddrBits];
    for (var i=0; i<vochainAddrBits; i++) {
        addrBits[i] = n2b.out[i];
    }
    // Return the binary address to its decimal representation
    component b2n = Bits2Num(vochainAddrBits);
    b2n.in <== addrBits;
    b2n.out ==> address;
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

	// compute publicKey
	component babyPbk = BabyPbk();
	babyPbk.in <== privateKey;

	// compute keyHash, which will be at the leaf
	component keyHash = Poseidon(2);
	keyHash.inputs[0] <== babyPbk.Ax;
	keyHash.inputs[1] <== babyPbk.Ay;

	component vochainAddr = ZkAddress();
    vochainAddr.keyHash <== keyHash.out;

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
	smtClaimExists.key <-- vochainAddr.address;
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
