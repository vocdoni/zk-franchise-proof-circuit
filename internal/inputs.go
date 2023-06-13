package internal

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

type circuitInputs struct {
	// Public inputs
	ElectionId      []string `json:"electionId"`
	Nullifier       string   `json:"nullifier"`
	AvailableWeight string   `json:"availableWeight"`
	VoteHash        []string `json:"voteHash"`
	CIKRoot         string   `json:"cikRoot"`
	CensusRoot      string   `json:"censusRoot"`

	// Private inputs
	Address   string `json:"address"`
	Password  string `json:"password"`
	Signature string `json:"signature"`

	VoteWeight     string   `json:"voteWeight"`
	CensusSiblings []string `json:"censusSiblings"`
	CIKSiblings    []string `json:"cikSiblings"`
}

func MockInputs(nLevels, nKeys int) (circuitInputs, error) {
	// test with dummy personal signature generated with metamask.github.io/test-dapp
	msg := []byte("Example `personal_sign` message")
	password := util.RandomBytes(32)
	availableWeight := big.NewInt(10)
	signature, err := hex.DecodeString("3a7806f4e0b5bda625d465abf5639ba42ac9b91bafea3b800a4afff840be8d55333c286c7e21c91850a99efb5008847eaf653e3a5776f64f4d3b405afd5dcde61c")
	if err != nil {
		return circuitInputs{}, err
	}
	// get address from the signature
	address, err := ethereum.AddrFromSignature(msg, signature)
	if err != nil {
		return circuitInputs{}, err
	}
	// generate tree for the census
	censusRoot, _, censusSiblings, err := GenTree("census", address.Bytes(), availableWeight.Bytes(), 10)
	if err != nil {
		log.Fatal("0 - ", err)
		return circuitInputs{}, err
	}
	strCensusSiblings := make([]string, len(censusSiblings))
	for i, s := range censusSiblings {
		strCensusSiblings[i] = s.String()
	}
	strCensusSiblings = append(strCensusSiblings, "0")
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
		return circuitInputs{}, err
	}
	// generate tree for the cik's
	cikRoot, _, cikSiblings, err := GenTree("cik", address.Bytes(), arbo.BigIntToBytes(arbo.HashFunctionPoseidon.Len(), cik), 10)
	if err != nil {
		return circuitInputs{}, err
	}
	strCIKSiblings := make([]string, len(cikSiblings))
	for i, s := range cikSiblings {
		strCIKSiblings[i] = s.String()
	}
	strCIKSiblings = append(strCIKSiblings, "0")
	// generate the electionId and calculate nullifier =>
	// H(signature, password, electionId)
	electionId := BytesToArbo(util.RandomBytes(32))
	nullifier, err := poseidon.Hash([]*big.Int{ffSignature, ffPassword, electionId[0], electionId[1]})
	if err != nil {
		return circuitInputs{}, err
	}
	// generate vote hash and encode inputs
	voteHash := BytesToArbo(availableWeight.Bytes())
	return circuitInputs{
		ElectionId:      []string{electionId[0].String(), electionId[1].String()},
		Nullifier:       nullifier.String(),
		AvailableWeight: availableWeight.String(),
		VoteHash:        []string{voteHash[0].String(), voteHash[1].String()},
		CIKRoot:         cikRoot.String(),
		CensusRoot:      censusRoot.String(),

		Address:   arbo.BytesToBigInt(address.Bytes()).String(),
		Password:  ffPassword.String(),
		Signature: ffSignature.String(),

		VoteWeight:     big.NewInt(5).String(),
		CensusSiblings: strCensusSiblings,
		CIKSiblings:    strCIKSiblings,
	}, nil
}

func (inputs *circuitInputs) Bytes() []byte {
	b, _ := json.MarshalIndent(inputs, "", "\t")
	return b
}

func (inputs *circuitInputs) String() string {
	return string(inputs.Bytes())
}
