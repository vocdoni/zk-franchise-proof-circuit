package internal

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/tree/arbo"
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
	password, _ := new(big.Int).SetString("df8634ab3b14536cb7a6953b1128ec6742726483bc5bb13605891600fd5ec35b", 16)
	availableWeight := big.NewInt(10)
	signature, _ := new(big.Int).SetString("3a7806f4e0b5bda625d465abf5639ba42ac9b91bafea3b800a4afff840be8d55333c286c7e21c91850a99efb5008847eaf653e3a5776f64f4d3b405afd5dcde61c", 16)
	// get address from the signature
	address, err := ethereum.AddrFromSignature(msg, signature.Bytes())
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
	ffPassword := BigToFF(password)
	ffSignature := BigToFF(signature)
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
	// electionId := BytesToArbo(util.RandomBytes(32))
	electionId, _ := hex.DecodeString("7faeab7a7d250527d614e952ae8e446825bd1124c6def410844c7c383d1519a6")
	ffElectionId := BytesToArbo(electionId)
	nullifier, err := poseidon.Hash([]*big.Int{ffSignature, ffPassword, ffElectionId[0], ffElectionId[1]})
	if err != nil {
		return circuitInputs{}, err
	}
	// generate vote hash and encode inputs
	voteHash := BytesToArbo(availableWeight.Bytes())
	return circuitInputs{
		ElectionId:      []string{ffElectionId[0].String(), ffElectionId[1].String()},
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
