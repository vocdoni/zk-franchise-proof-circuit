include "../za/interop/circuits/circomlib/circuits/comparators.circom";
include "../za/interop/circuits/circomlib/circuits/eddsaposeidon.circom";
include "../za/interop/circuits/circomlib/circuits/smt/smtverifier.circom";

template NullifierMultisig(N) {

    signal input  commitment[N];
    signal input  nullifier[N];
    signal output success;

    component pvk2pbk[N];
    component pbkcheck[N];
    signal    count[N];

    for (var n=0;n<N;n+=1) {
        pvk2pbk[n] = BabyPbk();
        pvk2pbk[n].in <== nullifier[n];

        pbkcheck[n] = IsEqual();
        pbkcheck[n].in[0] <== pvk2pbk[n].Ax;
        pbkcheck[n].in[1] <== commitment[n];

        if (n == 0) {
            count[0] <== pbkcheck[n].out;
        } else {
            count[n] <== pbkcheck[n].out + count[n-1];
        }
    }

    component countcheck = IsEqual();
    countcheck.in[0] <== count[N-1];
    countcheck.in[1] <== N;

    success <== countcheck.out;
}


template FranchiseProof(nLevels, nAuth) {

    signal         input censusRoot;
    signal private input censusSiblings[nLevels];
    signal private input censusIdx;

    signal private input voteSigS;
    signal private input voteSigR8x;
    signal private input voteSigR8y;

    signal         input voteValue;

    signal private input privateKey;
    
    signal         input votingId;
    signal         input nullifier;

    signal         input gcommitment[nAuth];
    signal private input gnullifier[nAuth];

    component gnullcheck = NullifierMultisig(nAuth);
    for (var n=0;n<nAuth;n+=1)  {
        gnullcheck.commitment[n] <== gcommitment[n];
        gnullcheck.nullifier[n] <== gnullifier[n];
    }
    
    signal verify;
    verify <== 1 - gnullcheck.success;

    // -- extract public key -------------------------------------------
    component pbk = BabyPbk();
    pbk.in <== privateKey;

    // -- verify vote signature  ---------------------------------------
    component sigVerification = EdDSAPoseidonVerifier();
    
    sigVerification.enabled <== verify;
    
    // signer public key (extract from private key)
    sigVerification.Ax <== pbk.Ax;
    sigVerification.Ay <== pbk.Ay;

    // signature (coordinates)
    sigVerification.S <== voteSigS;
    sigVerification.R8x <== voteSigR8x;
    sigVerification.R8y <== voteSigR8y;

    // message
    sigVerification.M <== voteValue;

    // -- verify public key is in census merkle tree ---------------------
    
    component smtCensusInclusion = SMTVerifier(nLevels);
    smtCensusInclusion.enabled <== verify;

    // check for inclusion (0 => VERIFY INCLUSION, 1=>VERIFY EXCLUSION)
    smtCensusInclusion.fnc <== 0;

    // *old* parameters are not used (only works for EXCLUSION case)
    smtCensusInclusion.oldKey <== 0;
    smtCensusInclusion.oldValue <== 0;
    smtCensusInclusion.isOld0 <== 0;

    // root and siblings
    smtCensusInclusion.root <== censusRoot;
    for (var i=0; i<nLevels; i+=1) {
        smtCensusInclusion.siblings[i] <==  censusSiblings[i];
    }

    // key and value 
    smtCensusInclusion.key <== censusIdx;

    component hashAxAy = Poseidon(2,6,8,57);
    hashAxAy.inputs[0] <== pbk.Ax;
    hashAxAy.inputs[1] <== pbk.Ay;
    smtCensusInclusion.value <== hashAxAy.out;

    // -- verify nullifier integrity -----------------------------------
    component hashPvkVid = Poseidon(2,6,8,57);
    hashPvkVid.inputs[0] <== privateKey;
    hashPvkVid.inputs[1] <== votingId ;
    
    component nullifierCheck = ForceEqualIfEnabled();
    nullifierCheck.enabled <== verify;
    nullifierCheck.in[0] <== nullifier;
    nullifierCheck.in[1] <== hashPvkVid.out;
}
