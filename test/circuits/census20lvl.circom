pragma circom 2.0.0;

include "../../circuits/census.circom";

component main {public [processId, censusRoot, nullifier, voteHash]}= Census(20);
