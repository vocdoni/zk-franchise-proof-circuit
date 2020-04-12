/*
# credential.circom

Circuit to check:
- the prover is the owner of the private key
- the public key of the private key is inside a ClaimCensus, which is inside the Merkletree with the CensusRoot
- H(privateKey, electionID) == nullifier

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
                          | Verifier |                    +----+
   PRI_siblings+--------->+          |
                          |          |
                          +----------+

	// TODO PRI_revealKey
	// TODO PUB_commitKey

*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";

/* include "../node_modules/iden3/circuits/circuits/buildClaimKeyBBJJ.circom"; // TODO import from iden3/circuits */

template Census(nLevels) { // nAuth
	signal input censusRoot;
	signal private input censusSiblings[nLevels];
	signal private input privateKey;

	signal private input voteSigS;
	signal private input voteSigR8x;
	signal private input voteSigR8y;

	signal input voteValue;

	signal input electionId;
	signal input nullifier;

	// TODO revealKey & commitKey


	// compute Public Key
	component babyPbk = BabyPbk();
	babyPbk.in <== privateKey;

	// verify vote signature
	component signVerification = EdDSAPoseidonVerifier();
	signVerification.enabled <== 1 // tmp depends on nullifier-multisig
	sigVerification.Ax <== babyPbk.Ax;
	sigVerification.Ay <== babyPbk.Ay;
	sigVerification.S <== voteSigS;
	sigVerification.R8x <== voteSigR8x;
	sigVerification.R8y <== voteSigR8y;
	sigVerification.M <== voteValue;

	// build ClaimCensus
	component claimCensus = BuildClaimAuthKSignBBJJ();
	claimCensus.sign <== 1; // TODO
	claimCensus.ay <== babyPbk.Ay;

	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1; // tmp depends on nullifier-multisig
	smtClaimExists.fnc <== 0; // 0 as is to verify inclusion
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== censusSiblings[nLevels];
	}
	smtClaimExists.key <== claim.hi;
	smtClaimExists.value <== claim.hv;
}
