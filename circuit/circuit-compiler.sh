#!/bin/sh

# color characters and functions to pretty print
Color_Off='\033[0m'
Red='\033[0;31m'
Purple='\033[0;35m'
log() {
	echo "${Purple}[CIRCUIT-COMPILER:INFO]${Color_Off} $1"
}
error() {
	echo "${Red}[CIRCUIT-COMPILER:ERROR]${Color_Off} $1"
}

# env vars
ENVIRONMENT="${ENVIRONMENT:-dev}"

# resolve paths of binaries
CIRCOM=circom
HASH=sha256sum
SNARKJS="$(readlink -f "./node_modules/.bin/snarkjs")"

# resolve paths of inputs and outputs
CIRCUIT_NAME="${2:-zkCensus}"
CIRCUIT=$(readlink -f "$1")
ARTIFACTS="$(readlink -f "$PWD/../artifacts/$CIRCUIT_NAME")"
TRASH="$PWD/toxic-waste/$CIRCUIT_NAME"

# check if the provided command as argument is already installed
try_or_exit() {
	if [ ! command -v $1 &> /dev/null ]; then 
		error "$(basename $1) is not installed, install it to continue"
		exit
	fi
}

# check if the required commands are available and create some required folders
initial_setup() {
	try_or_exit $SNARKJS
	try_or_exit $CIRCOM
	try_or_exit $HASH

	mkdir -p $ARTIFACTS/$ENVIRONMENT
	echo "" > "$ARTIFACTS/$ENVIRONMENT/circuits-info.md"
}

# remove unnecesary files after complete the process
clean() {
	rm -rf $ARTIFACTS/$ENVIRONMENT/*/circuit_js $ARTIFACTS/$ENVIRONMENT/*/*.js
}

# perform the porwer of tau ceremony
power_of_tau() {
	if [ ! -d "$TRASH" ] || [ ! "$(ls -A $TRASH)" ]; then	
		log "computing power-of-tau..."
		mkdir -p $TRASH
		# create the ceremony
		$SNARKJS powersoftau new bn128 20 $TRASH/pot12_0000.ptau -v
		# first contribution
		$SNARKJS powersoftau contribute $TRASH/pot12_0000.ptau $TRASH/pot12_0001.ptau --name="First contribution" -v -e
		# second contribution
		$SNARKJS powersoftau contribute $TRASH/pot12_0001.ptau $TRASH/pot12_0002.ptau --name="Second contribution" -v -e=random
		# third contribution (external)
		$SNARKJS powersoftau export challenge $TRASH/pot12_0002.ptau $TRASH/challenge_0003
		$SNARKJS powersoftau challenge contribute bn128 $TRASH/challenge_0003 $TRASH/response_0003 -e=random
		$SNARKJS powersoftau import response $TRASH/pot12_0002.ptau $TRASH/response_0003 $TRASH/pot12_0003.ptau -n="Third contribution"
		# verify
		$SNARKJS powersoftau verify $TRASH/pot12_0003.ptau
		# apply a random beacon
		$SNARKJS powersoftau beacon $TRASH/pot12_0003.ptau $TRASH/pot12_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
		# prepare phase 2
		$SNARKJS powersoftau prepare phase2 $TRASH/pot12_beacon.ptau $TRASH/pot12_final.ptau -v
		# verify
		$SNARKJS powersoftau verify $TRASH/pot12_final.ptau
	else 
		log "power-of-tau found, skipping computation..."
	fi
}

# compile the circuit to generate the r1cs and wasm versions
compile_circuit() {
	NLEVELS=$1
	mkdir -p $ARTIFACTS/$ENVIRONMENT/$NLEVELS
	log "creating circuit to compile based on the provided one by the user"

	CIRCUITCODE="pragma circom 2.0.0;
include \"$CIRCUIT\";
component main {public [processId, censusRoot, nullifier, voteHash, weight]} = Census($NLEVELS);"
	echo "$CIRCUITCODE" > $TRASH/circuit.circom

	# compilling the circuit
	$CIRCOM $TRASH/circuit.circom --r1cs --wasm --sym -o $ARTIFACTS/$ENVIRONMENT/$NLEVELS
	# print circuit info
	$SNARKJS r1cs info $ARTIFACTS/$ENVIRONMENT/$NLEVELS/circuit.r1cs
	# move it to the correct folder
	mv $ARTIFACTS/$ENVIRONMENT/$NLEVELS/circuit_js/* $ARTIFACTS/$ENVIRONMENT/$NLEVELS
}

# usign the power of tau files and the compiled circuit, generate the proving and verify keys
generate_proving_key() {
	NLEVELS=$1
	mkdir -p $TRASH/$ENVIRONMENT/$NLEVELS
	log "computing proving and verification keys..."

	# create the trusted setup
	$SNARKJS groth16 setup $ARTIFACTS/$ENVIRONMENT/$NLEVELS/circuit.r1cs $TRASH/pot12_final.ptau $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0000.zkey
	# perform the first contribution
	$SNARKJS zkey contribute $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0000.zkey $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0001.zkey --name="1st Contribution" -v -e=random2
	# perform the second contribution
	$SNARKJS zkey contribute $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0001.zkey $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0002.zkey --name="2nd Contribution" -v -e=random2
	# perform the third contribution (external)
	$SNARKJS zkey export bellman $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0002.zkey $TRASH/$ENVIRONMENT/$NLEVELS/challenge_phase2_0003
	$SNARKJS zkey bellman contribute bn128 $TRASH/$ENVIRONMENT/$NLEVELS/challenge_phase2_0003 $TRASH/$ENVIRONMENT/$NLEVELS/response_phase2_0003 -e="some random text"
	$SNARKJS zkey import bellman $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0002.zkey $TRASH/$ENVIRONMENT/$NLEVELS/response_phase2_0003 $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0003.zkey -n="3rd Contribution"
	# apply a random beacon
	$SNARKJS zkey beacon $TRASH/$ENVIRONMENT/$NLEVELS/circuit_0003.zkey $ARTIFACTS/$ENVIRONMENT/$NLEVELS/proving_key.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
	# verify the final zkey
	$SNARKJS zkey verify $ARTIFACTS/$ENVIRONMENT/$NLEVELS/circuit.r1cs $TRASH/pot12_final.ptau $ARTIFACTS/$ENVIRONMENT/$NLEVELS/proving_key.zkey
	# export verification key
	$SNARKJS zkey export verificationkey $ARTIFACTS/$ENVIRONMENT/$NLEVELS/proving_key.zkey $ARTIFACTS/$ENVIRONMENT/$NLEVELS/verification_key.json
}

# compute the hashes of the files generated and store into a markdown file to be consulted
compute_hashes() {
	NLEVELS=$1
	CHECKSUMS_FILE="$ARTIFACTS/$ENVIRONMENT/circuits-info.md"
	log "computing files hashes..."
	
	ZKEY="$ARTIFACTS/$ENVIRONMENT/$NLEVELS/proving_key.zkey"
	VKEY="$ARTIFACTS/$ENVIRONMENT/$NLEVELS/verification_key.json"
	WASM="$ARTIFACTS/$ENVIRONMENT/$NLEVELS/circuit.wasm"

	if [ ! -f "$ZKEY" ]; then
		error "could not compute hash, $ZKEY file not found"
		exit
	elif [ ! -f "$VKEY" ]; then
		error "could not compute hash, $VKEY file not found"
		exit
	elif [ ! -f "$WASM" ]; then
		error "could not compute hash, $WASM file not found"
		exit
	fi

	echo "\n## circuit: $ENVIRONMENT ($NLEVELS nLevels) file hashes (sha256) " >> $CHECKSUMS_FILE
	echo "\`\`\`" >> $CHECKSUMS_FILE
	ZKEY_HASH=$($HASH $ZKEY)
	echo "${ZKEY_HASH/"$ARTIFACTS"}" >> $CHECKSUMS_FILE
	VKEY_HASH=$($HASH $VKEY)
	echo "${VKEY_HASH/"$ARTIFACTS"}" >> $CHECKSUMS_FILE
	CIRCUIT_HASH=$($HASH $WASM)
	echo "${CIRCUIT_HASH/"$ARTIFACTS"}" >> $CHECKSUMS_FILE
	echo "\`\`\`" >> $CHECKSUMS_FILE
}

main() {
	initial_setup
	power_of_tau

	versions=( 3 4 10 16 250 )
	for nlevels in "${versions[@]}"
	do
		compile_circuit $nlevels || error "error compiling circuits for $nlevels leves and $ENVIRONMENT environment"
		generate_proving_key $nlevels || error "error generating proving and verification keys for $nlevels leves and $ENVIRONMENT environment"
		compute_hashes $nlevels
	done
	clean
}

main