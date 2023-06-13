pragma circom 2.1.2;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/smt/smtverifier.circom";

/**
                                                   ┌───────────┐
                              ┌────────────────────▶lessOrEqual├──────────┐
      (priv) voteWeight───────┘                    └─────▲─────┘          │
                                                         │                │
  (pub) availableWeight─┬────────────────────────────────┘                │
                        │                                                 │    ┌────┐
                        │                                                 └───▶│    └┐
                        │       ┌────────────────────┐                 ┌──────▶│     └┐
                        │  ┌────▶key                 │                 │       │      ├─
                        └──│────▶value               │                 │   ┌──▶│     ┌┘
                           │    │         SMTVerifier├─────────────────┘ ┌────▶│    ┌┘
       (pub) censusRoot────│────▶root                │                   │ │   └────┘
                        ┌──│────▶siblings            │                   │ │
  (priv) censusSiblings─┘  │    └────────────────────┘                   │ │
                           │                     ┌────────────────────┐  │ │
                           │   ┌─────────────────▶key                 │  │ │
                           │   │               ┌─▶value               │  │ │
                           │   │               │ │         SMTVerifier├──│─┘
          (pub) cikRoot────│─────────────────────▶root                │  │
                           │   ┌─────────────────▶siblings            │  │
     (priv) cikSiblings────│───┘               │ └────────────────────┘  │
                           │   │               │                         │
                           │   │               │                         │
                           │   │               │                         │
         (priv) address────┼───┘ ┌────────────┐│                         │
                           ├────▶│            ││                         │
        (priv) password────│────▶│    Hash    ├┘                         │
                        ┌──│────▶│            │                          │
       (priv) signature─┤  │     └────────────┘                          │
                        │  │                                             │
                        │  │     ┌────────────┐                          │
                        │  └────▶│            │                          │
                        └───────▶│    Hash    ├──────────┐               │
                           ┌────▶│            │          │               │
                           │     └────────────┘          │               │
       (pub) electionId────┘                             │               │
                                                   ┌─────▼─────┐         │
        (pub) nullifier────────────────────────────▶   equal   ├─────────┘
                                                   └───────────┘                        
*/

template ZkFranchiseProofCircuit (nLevels) {
    var realNLevels = nLevels+1;
    signal input electionId[2];
    signal input nullifier;
    signal input availableWeight;
    // voteHash is not operated inside the circuit, assuming that in
	// Circom an input that is not used will be included in the constraints
	// system and in the witness
    signal input voteHash[2];
    signal input cikRoot;
    signal input censusRoot;

    signal input address;
    signal input password;
    signal input signature;

    signal input voteWeight;
    signal input censusSiblings[realNLevels];
    signal input cikSiblings[realNLevels];
    
    component checkWeight = LessEqThan(252);
    checkWeight.in[0] <== voteWeight;
    checkWeight.in[1] <== availableWeight;
    checkWeight.out === 1;
    
    component cik = Poseidon(3);
	cik.inputs[0] <== address;
	cik.inputs[1] <== password;
    cik.inputs[2] <== signature;

    component cikVerifier = SMTVerifier(realNLevels);
	cikVerifier.enabled <== 1;
	cikVerifier.fnc <== 0; // 0 as is to verify inclusion
	cikVerifier.root <== cikRoot;
	for (var i=0; i<realNLevels; i++) {
		cikVerifier.siblings[i] <== cikSiblings[i];
	}
	cikVerifier.oldKey <== 0;
	cikVerifier.oldValue <== 0;
	cikVerifier.isOld0 <== 0;
	cikVerifier.key <== address;
	cikVerifier.value <== cik.out;

    component censusVerifier = SMTVerifier(realNLevels);
	censusVerifier.enabled <== 1;
	censusVerifier.fnc <== 0; // 0 as is to verify inclusion
	censusVerifier.root <== censusRoot;
	for (var i=0; i<realNLevels; i++) {
		censusVerifier.siblings[i] <== censusSiblings[i];
	}
	censusVerifier.oldKey <== 0;
	censusVerifier.oldValue <== 0;
	censusVerifier.isOld0 <== 0;
	censusVerifier.key <== address;
	censusVerifier.value <== availableWeight;

    component computedNullifier = Poseidon(4);
	computedNullifier.inputs[0] <== signature;
    computedNullifier.inputs[1] <== password;
	computedNullifier.inputs[2] <== electionId[0];
	computedNullifier.inputs[3] <== electionId[1];

    component checkNullifier = ForceEqualIfEnabled();
	checkNullifier.enabled <== 1;
	checkNullifier.in[0] <== computedNullifier.out;
	checkNullifier.in[1] <== nullifier;
}

// component main { public [ electionId, nullifier, availableWeight, voteHash, cikRoot, censusRoot ] } = ZkFranchiseProofCircuit(160);