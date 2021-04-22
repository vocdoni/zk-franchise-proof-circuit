SNARKJS=../node_modules/.bin/snarkjs 
CIRCOM=../node_modules/.bin/circom 
PLONKIT=plonkit1/target/release/plonkit

all: proof.bin plonkit/setup.txt plonkit/r1cs.txt plonkit/witness.txt

$(PLONKIT):
	git clone https://github.com/Fluidex/plonkit.git plonkit1
	(cd plonkit1 && git checkout 6e6236c4df4e0c63ab8565671d4033b0fde6325d && cargo build --release )

plonkit/setup.txt: setup.key
	base64 setup.key > plonkit/setup.txt

plonkit/r1cs.txt: circuit.r1cs
	base64 circuit.r1cs > plonkit/r1cs.txt

plonkit/witness.txt: witness.bin
	base64 witness.bin > plonkit/witness.txt

setup.key: $(PLONKIT)
	$(PLONKIT) setup --power 20 --srs_monomial_form setup.key

witness.bin: circuit.wasm input.json
	$(SNARKJS) calculatewitness --wasm circuit.wasm --input input.json --witness witness.bin

vk.bin: setup.key circuit.r1cs
	$(PLONKIT) export-verification-key -m setup.key -c circuit.r1cs -v vk.bin

proof.bin proof.json: vk.bin witness.bin
	$(PLONKIT) prove -m setup.key -c circuit.r1cs -w witness.bin -p proof.bin -j proof.json -i public_input.json
	$(PLONKIT) verify -p proof.bin -v vk.bin

circuit.wasm circuit.r1cs: circuit.circom
	$(CIRCOM) circuit.circom --r1cs circuit.r1cs --wasm circuit.wasm --sym circuit.sym -v

