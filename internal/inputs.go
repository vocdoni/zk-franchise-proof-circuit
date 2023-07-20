package internal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/crypto/zk"
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
	msg := []byte("Vocdoni Sik Seed")
	availableWeight := big.NewInt(10)

	electionId, _ := hex.DecodeString("7faeab7a7d250527d614e952ae8e446825bd1124c6def410844c7c383d1519a6")
	account := ethereum.NewSignKeys()
	if err := account.Generate(); err != nil {
		return circuitInputs{}, err
	}
	privKey := account.PrivateKey()
	signature, _ := account.SignEthereum(msg)
	log.Printf("Election: 0x%s\nAccount:\n\t- Address: %s\n\t- PrivKey: %s\n\t- Signature: %x\n",
		electionId, account.Address().String(), privKey.String(), signature)

	// generate tree for the census
	censusRoot, _, censusSiblings, err := GenTree("census", account.Address().Bytes(), availableWeight.Bytes(), 10)
	if err != nil {
		return circuitInputs{}, err
	}
	strCensusSiblings := make([]string, len(censusSiblings))
	for i, s := range censusSiblings {
		strCensusSiblings[i] = s.String()
	}
	strCensusSiblings = append(strCensusSiblings, "0")
	// generate tree for the sik's
	accountSik, err := account.Sik()
	if err != nil {
		return circuitInputs{}, err
	}
	fmt.Println(hex.EncodeToString(accountSik))
	sikRoot, _, sikSiblings, err := GenTree("sik", account.Address().Bytes(), accountSik, 10)
	if err != nil {
		return circuitInputs{}, err
	}
	strSIKSiblings := make([]string, len(sikSiblings))
	for i, s := range sikSiblings {
		strSIKSiblings[i] = s.String()
	}
	strSIKSiblings = append(strSIKSiblings, "0")
	// generate the electionId and calculate nullifier =>
	// H(signature, password, electionId)
	// electionId := BytesToArbo(util.RandomBytes(32))
	ffElectionId := BytesToArbo(electionId)
	nullifier, err := account.Nullifier(electionId, nil)
	if err != nil {
		return circuitInputs{}, err
	}
	// generate vote hash and encode inputs
	voteHash := BytesToArbo(availableWeight.Bytes())
	return circuitInputs{
		ElectionId:      []string{ffElectionId[0].String(), ffElectionId[1].String()},
		Nullifier:       new(big.Int).SetBytes(nullifier).String(),
		AvailableWeight: availableWeight.String(),
		VoteHash:        []string{voteHash[0].String(), voteHash[1].String()},
		CIKRoot:         sikRoot.String(),
		CensusRoot:      censusRoot.String(),

		Address:   arbo.BytesToBigInt(account.Address().Bytes()).String(),
		Password:  "0",
		Signature: zk.BigToFF(new(big.Int).SetBytes(signature)).String(),

		VoteWeight:     big.NewInt(5).String(),
		CensusSiblings: strCensusSiblings,
		CIKSiblings:    strSIKSiblings,
	}, nil
}

func (inputs *circuitInputs) Bytes() []byte {
	b, _ := json.MarshalIndent(inputs, "", "\t")
	return b
}

func (inputs *circuitInputs) String() string {
	return string(inputs.Bytes())
}
