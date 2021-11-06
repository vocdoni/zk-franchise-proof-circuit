SNARKJS=../node_modules/.bin/snarkjs 
CIRCOM=circom 
BUILD=build
RELEASE=release

all: $(RELEASE)/circuit.wasm \
     $(RELEASE)/circuit_final.zkey \
     $(RELEASE)/verification_key.json \
     $(RELEASE)/snarkjs.min.js \
     $(RELEASE)/index.html

$(BUILD):
	mkdir $(BUILD)

$(RELEASE):
	mkdir $(RELEASE)

$(RELEASE)/snarkjs.min.js: $(RELEASE)
	cp ../node_modules/snarkjs/build/snarkjs.min.js $(RELEASE)

$(RELEASE)/index.html: $(RELEASE)
	cp index.html $(RELEASE)

$(RELEASE)/circuit_final.zkey $(RELEASE)/verification_key.json: $(BUILD)/ $(BUILD)/circuit.r1cs $(BUILD)/pot_final.ptau
	$(SNARKJS) zkey new $(BUILD)/circuit.r1cs $(BUILD)/pot_final.ptau $(BUILD)/circuit_0000.zkey
	$(SNARKJS) zkey contribute $(BUILD)/circuit_0000.zkey $(BUILD)/circuit_0001.zkey --name=contributor -v -e=random2
	$(SNARKJS) zkey verify $(BUILD)/circuit.r1cs $(BUILD)/pot_final.ptau $(BUILD)/circuit_0001.zkey
	$(SNARKJS) zkey beacon $(BUILD)/circuit_0001.zkey $(RELEASE)/circuit_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n=Final
	$(SNARKJS) zkey verify $(BUILD)/circuit.r1cs $(BUILD)/pot_final.ptau $(RELEASE)/circuit_final.zkey
	$(SNARKJS) zkey export verificationkey $(RELEASE)/circuit_final.zkey $(RELEASE)/verification_key.json

$(RELEASE)/circuit.wasm $(BUILD)/circuit.r1cs: $(BUILD) $(RELEASE) circuit.circom
	$(CIRCOM) circuit.circom --r1cs --wasm --sym
	cp circuit.r1cs $(BUILD)/circuit.r1cs
	cp circuit_js/circuit.wasm $(BUILD)/circuit.wasm
	cp circuit_js/circuit.wasm $(RELEASE)/circuit.wasm
	cp circuit.sym $(BUILD)/circuit.sym
	../node_modules/browserify/bin/cmd.js circuit_js/witness_calculator.js --standalone WitnessCalc > release/witness_calculator_bundle.js

$(BUILD)/pot_final.ptau: $(BUILD)
	$(SNARKJS) powersoftau new bn128 15 $(BUILD)/pot_0000.ptau -v
	$(SNARKJS) powersoftau contribute $(BUILD)/pot_0000.ptau $(BUILD)/pot_0001.ptau --name=contribution -v -e=random
	$(SNARKJS) powersoftau beacon $(BUILD)/pot_0001.ptau $(BUILD)/pot_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n=Final
	$(SNARKJS) powersoftau prepare phase2 $(BUILD)/pot_beacon.ptau $(BUILD)/pot_final.ptau -v
	$(SNARKJS) powersoftau verify $(BUILD)/pot_final.ptau

open:
	( cd release && live-server )

clean:
	rm -rf $(BUILD)
