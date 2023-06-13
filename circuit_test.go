package zkfranchiseproofcircuit

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

var nLevels = flag.Int("nLevels", 160, "number of levels of the arbo tree")
var nKeys = flag.Int("nKyes", 10, "number of keys to add to the arbo tree")

func successInputs(nLevels, nKeys int) (ZkFranchiseProofCircuit, error) {
	// test with dummy personal signature generated with metamask.github.io/test-dapp
	msg := []byte("Example `personal_sign` message")
	password := util.RandomBytes(32)
	factoryWeight := big.NewInt(10)
	signature, err := hex.DecodeString("3a7806f4e0b5bda625d465abf5639ba42ac9b91bafea3b800a4afff840be8d55333c286c7e21c91850a99efb5008847eaf653e3a5776f64f4d3b405afd5dcde61c")
	if err != nil {
		return ZkFranchiseProofCircuit{}, err
	}
	// get address from the signature
	address, err := ethereum.AddrFromSignature(msg, signature)
	if err != nil {
		return ZkFranchiseProofCircuit{}, err
	}
	// generate tree for the census
	censusRoot, nCensusSiblings, censusSiblings, err := GenTree("census", address.Bytes(), factoryWeight.Bytes(), 10)
	if err != nil {
		log.Fatal("0 - ", err)
		return ZkFranchiseProofCircuit{}, err
	}
	vcensusSiblings := [160]frontend.Variable{}
	for i, s := range censusSiblings {
		vcensusSiblings[i] = s
	}
	// ensure that the password and signature are in the FF
	ffPassword := BytesToFF(password)
	ffSignature := BytesToFF(signature)
	// calculate the cik => H(address, password, signature)
	cik, err := poseidon.Hash([]*big.Int{
		arbo.BytesToBigInt(address.Bytes()),
		ffPassword,
		ffSignature,
	})
	if err != nil {
		return ZkFranchiseProofCircuit{}, err
	}
	// generate tree for the cik's
	cikRoot, nCIKSiblings, cikSiblings, err := GenTree("cik", address.Bytes(), arbo.BigIntToBytes(arbo.HashFunctionPoseidon.Len(), cik), 10)
	if err != nil {
		return ZkFranchiseProofCircuit{}, err
	}
	vcikSiblings := [160]frontend.Variable{}
	for i, s := range cikSiblings {
		vcikSiblings[i] = s
	}
	// generate the electionId and calculate nullifier =>
	// H(signature, password, electionId)
	electionId := BytesToArbo(util.RandomBytes(32))
	nullifier, err := poseidon.Hash([]*big.Int{ffSignature, ffPassword, electionId[0], electionId[1]})
	if err != nil {
		return ZkFranchiseProofCircuit{}, err
	}
	// generate vote hash and encode inputs
	voteHash := BytesToArbo(factoryWeight.Bytes())
	return ZkFranchiseProofCircuit{
		ElectionId:    [2]frontend.Variable{electionId[0], electionId[1]},
		Nullifier:     nullifier,
		FactoryWeight: factoryWeight,
		VoteHash:      [2]frontend.Variable{voteHash[0], voteHash[1]},
		CIKRoot:       cikRoot,
		CensusRoot:    censusRoot,

		Address:   arbo.BytesToBigInt(address.Bytes()),
		Password:  ffPassword,
		Signature: ffSignature,

		VotingWeight:    big.NewInt(5),
		CensusSiblings:  vcensusSiblings,
		NCensusSiblings: nCensusSiblings,
		CIKSiblings:     vcikSiblings,
		NCIKSiblings:    nCIKSiblings,
	}, nil
}

func (circuit *ZkFranchiseProofCircuit) String() string {
	s, _ := json.MarshalIndent(circuit, "", "\t")
	return string(s)
}

func TestZkCensusCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit ZkFranchiseProofCircuit

	inputs, err := successInputs(*nLevels, *nKeys)
	assert.Nil(err)
	assert.SolvingSucceeded(&circuit, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
	assert.SolvingSucceeded(&circuit, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
