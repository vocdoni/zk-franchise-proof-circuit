# ZKSnark census circuit compiler & tester

This repo contains the required code to compile and test the [Vocdoni](https://vocdoni.io/) ZKSnark circuit to generate and verify a election census for anonymous voting. 

It also contains the current version of the [circuit](circuit/census.circom) (designed using [Circom](https://github.com/iden3/circom)). 

## Usage

### Requirments
To use this repo, the following requirements must be installed: 
* [Go](https://go.dev/)
* [NodeJS & NPM](https://nodejs.org/en/)
* [Coreutils (GNU core utilities)](https://www.gnu.org/software/coreutils/)
* [Circom](https://docs.circom.io/)

### Available commands

* **Install dependencies**

    It installs required script dependencies. To get the full list of dependencies read the [package.json](./circuit/package.json) and [go.mod](./go.mod).

    ```sh
    make install
    ```

* **Compile the circuit and generate artifacts**

    It compiles the circuit (read more [here](https://github.com/iden3/snarkjs#10-compile-the-circuit)), calculates the witness and export it (read more [here](https://github.com/iden3/snarkjs#14-calculate-the-witness)) and generates the zkey and export it (read more [here](https://github.com/iden3/snarkjs#15-setup)). The resulting artifacts will be at `./artifacts/<environment>/<nlevels>/`, check the checksums of the `dev` environment [here](./artifacts/dev/circuits-info.md).

    ```sh
    make compile
    ```

* **Test the proof generation and verification**

    It generates a valid set of circuit inputs, generates a zk-proof with them and verify that proof. All this steps use the result of circuit compilation, so they must be performed after executing the `make compile` command.

    ```sh
    make test
    ```

