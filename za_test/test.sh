ZA=../za/target/release/za
echo testing circuit ----------------------------------------------------------
$ZA test --circuit circuit.za
echo testing setup and generation ------------------------------------------------
$ZA setup --circuit ../test/circuits/testfranchiseproof.circom --pk /tmp/fp.key --verifier /tmp/fp.sol
$ZA prove --pk /tmp/fp.key --proof /tmp/proof.json
