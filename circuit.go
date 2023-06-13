package zkfranchiseproofcircuit

import (
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type ZkFranchiseProofCircuit struct {
	// Public inputs
	ElectionId    [2]frontend.Variable `gnark:",public"`
	Nullifier     frontend.Variable    `gnark:",public"`
	FactoryWeight frontend.Variable    `gnark:",public"`
	VoteHash      [2]frontend.Variable `gnark:",public"`
	CIKRoot       frontend.Variable    `gnark:",public"`
	CensusRoot    frontend.Variable    `gnark:",public"`

	// Private inputs
	Address   frontend.Variable
	Password  frontend.Variable
	Signature frontend.Variable

	VotingWeight    frontend.Variable
	CensusSiblings  [160]frontend.Variable
	NCensusSiblings frontend.Variable
	CIKSiblings     [160]frontend.Variable
	NCIKSiblings    frontend.Variable
}

func init() {
	hint.Register(arbo.ValidSiblings)
}

func (circuit *ZkFranchiseProofCircuit) Define(api frontend.API) error {
	// votingWeight represents the weight that the user wants to use to perform
	// a vote and must be lower than factoryWeight
	api.AssertIsLessOrEqual(circuit.VotingWeight, circuit.FactoryWeight)
	// voteHash is not operated inside the circuit, assuming that in
	// Circom an input that is not used will be included in the constraints
	// system and in the witness
	api.AssertIsDifferent(circuit.VoteHash[0], 0)
	api.AssertIsDifferent(circuit.VoteHash[1], 0)
	// compute cik => H(address, password, signature)
	cik := poseidon.Hash(api, circuit.Address, circuit.Password, circuit.Signature)
	// check the Merkletree with cik root, siblings, address and cik value
	if err := arbo.CheckProof(api, circuit.Address, cik, circuit.CIKRoot, circuit.NCIKSiblings, circuit.CIKSiblings[:]); err != nil {
		return err
	}
	// check the Merkletree with census root, siblings, zkKey and factory weight
	if err := arbo.CheckProof(api, circuit.Address, circuit.FactoryWeight, circuit.CensusRoot, circuit.NCensusSiblings, circuit.CensusSiblings[:]); err != nil {
		return err
	}
	// check the nullifier provided with the computed one =>
	// H(signature, password, electionId)
	computedNullifier := poseidon.Hash(api, circuit.Signature, circuit.Password, circuit.ElectionId[0], circuit.ElectionId[1])
	api.AssertIsEqual(circuit.Nullifier, computedNullifier)
	return nil
}
