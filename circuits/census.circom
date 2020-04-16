/*
# credential.circom

Circuit to check:
- the prover is the owner of the private key
- the public key of the private key is inside a ClaimCensus, which is inside the Merkletree with the CensusRoot
- H(privateKey, electionID) == nullifier
- H(nullifier, relayerPublicKey) == relayerProof
- n times (for each Miner) * H(revealKey) == commitKey OR the rest of the circuit


                       +-------------+
                       |             |
PRI_voteSig+---------->+  EDDSA      |
                       |  Signature  +<----------+
PUB_voteValue+-------->+  Verifier   |           |
                       |             |           |       +---------+
                       +-------------+           |       |         |
                                                 +-------+ pvk2pbk +<------+--+PRI_privateKey
                                                 |       |         |       |
                         +-------------+         |       +---------+       |
                         |             |         |                         |
                         | ClaimCensus +<--------+                         |
                         |             |              +----------+         |
                         +------+------+              |          +<--------+
                                |                     | Poseidon |
                                |                     |          +<-----------+PUB_electionID
                                |                     +-----+----+
                                v                           |
                          +-----+----+                      |
                          |          |                      v
                          |          |                    +-+--+
   PUB_censusRoot+------->+ SMT      |                    | == +<-------------+PUB_nullifier
                          | Verifier |                    +----+               +
   PRI_siblings+--------->+          |                                         |
                          |          |                         +----------+    |
                          +----------+                         |          +<---+
                                                          +----+ Poseidon |
                                                          |    |          +<--+PRI_relayerPublicKey
                                                          |    +----------+
                                                          v
                                                       +--+-+
                                                       | == +<----------------+PUB_relayerProof
                                                       +----+

     +--------------------------------------------OR-------------------------------------------+

                       /                        +----------+      +----+
                       + PRI_revealKey+-------->+ Poseidon +----->+ == |
              N miners |                        +----------+      +-+--+
                       |                                            ^
                       + PUB_commitKey+-----------------------------+
                       \


*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

/* include "../node_modules/iden3/circuits/circuits/buildClaimKeyBBJJ.circom"; // TODO import from iden3/circuits npm package */
include "buildClaimKeyBBJJ.circom"; // tmp

template Census(nLevels, nMiners) {
	signal input censusRoot;
	signal private input censusSiblings[nLevels];
	signal private input privateKey;

	signal private input voteSigS;
	signal private input voteSigR8x;
	signal private input voteSigR8y;

	signal input voteValue;

	signal input electionId;
	signal input nullifier;

	signal private input relayerPublicKey;
	signal input relayerProof;

	signal private input revealKey[nMiners];
	signal input commitKey[nMiners];

	component computedCommitKey[nMiners];
	component checkCommitKey[nMiners];
	component multiAnd = MultiAND(nMiners);
	for (var i=0; i<nMiners; i++) {
		computedCommitKey[i] = Poseidon(1, 6, 8, 57);
		computedCommitKey[i].inputs[0] <== revealKey[i];
		checkCommitKey[i] = IsEqual();
		checkCommitKey[i].in[0] <== computedCommitKey[i].out;
		checkCommitKey[i].in[1] <== commitKey[i];

		multiAnd.in[i] <== checkCommitKey[i].out;
	}
	signal verify;
	verify <== 1 - multiAnd.out;


	// compute Public Key
	component babyPbk = BabyPbk();
	babyPbk.in <== privateKey;

	// verify vote signature
	component sigVerification = EdDSAPoseidonVerifier();
	sigVerification.enabled <== verify;
	sigVerification.Ax <== babyPbk.Ax;
	sigVerification.Ay <== babyPbk.Ay;
	sigVerification.S <== voteSigS;
	sigVerification.R8x <== voteSigR8x;
	sigVerification.R8y <== voteSigR8y;
	sigVerification.M <== voteValue;

	// build ClaimCensus
	component claimCensus = BuildClaimKeyBBJJ(0);
	claimCensus.ax <== babyPbk.Ax;
	claimCensus.ay <== babyPbk.Ay;
	
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== verify;
	smtClaimExists.fnc <== 0; // 0 as is to verify inclusion
	smtClaimExists.root <== censusRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== censusSiblings[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimCensus.hi;
	smtClaimExists.value <== claimCensus.hv;

	// check nullifier
	component computedNullifier = Poseidon(2, 6, 8, 57);
	computedNullifier.inputs[0] <== privateKey;
	computedNullifier.inputs[1] <== electionId;
	component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== verify;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;

	// check relayerProof
	component computedRelayerProof = Poseidon(2, 6, 8, 57);
	computedRelayerProof.inputs[0] <== nullifier;
	computedRelayerProof.inputs[1] <== relayerPublicKey;
	component checkRelayerProof = ForceEqualIfEnabled();
	checkRelayerProof.enabled <== verify;
	checkRelayerProof.in[0] <== computedRelayerProof.out;
	checkRelayerProof.in[1] <== relayerProof;

}
