package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/censustree/arbotree"
)

func TestCensus(t *testing.T) {
	testCensus(t, "inputs0.json", 3, 0)
	testCensus(t, "inputs1.json", 9, 10)
	testCensus(t, "inputs2.json", 19, 1000)
}

func testCensus(t *testing.T, inputsFileName string, nLevels, nPaddingLeafs int) {
	fmt.Printf("%d levels, %d padding leafs\n", nLevels, nPaddingLeafs)

	// --- User side
	// -------------
	// new babyjubjub PrivateKey
	secretKeyStr := "3876493977147089964395646989418653640709890493868463039177063670701706079087"
	secretKey, ok := new(big.Int).SetString(secretKeyStr, 10)
	assert.True(t, ok)

	// --- Org side
	// ------------
	// new CensusTree
	censusTree, err := arbotree.NewTree("test0", t.TempDir(), nLevels, arbo.HashFunctionPoseidon)
	assert.Nil(t, err)

	secretKeyHashBI, err := poseidon.Hash([]*big.Int{
		secretKey,
	})
	bLen := arbo.HashFunctionPoseidon.Len()
	secretKeyHashBytes := arbo.BigIntToBytes(bLen, secretKeyHashBI)

	// add keyHash to CensusMerkleTree
	err = censusTree.Add(secretKeyHashBytes, []byte{0})
	assert.Nil(t, err)

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingLeafs; i++ {
		err = censusTree.Add(
			arbo.BigIntToBytes(bLen, big.NewInt(int64(i))),
			arbo.BigIntToBytes(bLen, big.NewInt(int64(i))))
		assert.Nil(t, err)
	}

	// get merkleproof
	proof, err := censusTree.GenProof(secretKeyHashBytes, []byte{0})
	assert.Nil(t, err)
	siblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, proof)
	assert.Nil(t, err)
	for i := len(siblings); i < nLevels; i++ {
		siblings = append(siblings, []byte{0})
	}
	siblings = append(siblings, []byte{0})
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		siblingsStr = append(siblingsStr, arbo.BytesToBigInt(siblings[i][:]).String())
	}
	jsonSiblings, err := json.Marshal(siblingsStr)
	assert.Nil(t, err)

	// get CensusRoot
	rootBytes := censusTree.Root()

	// --- User side
	// -------------
	vote := big.NewInt(1)

	// compute nullifier
	electionId := big.NewInt(10)
	nullifier, err := poseidon.Hash([]*big.Int{
		secretKey,
		electionId,
	})

	w := bytes.NewBufferString("")
	fmt.Fprintf(w, "{\n")
	fmt.Fprintf(w, `	"censusRoot": "%s",`+"\n", arbo.BytesToBigInt(rootBytes[:]))
	fmt.Fprintf(w, `	"censusSiblings": %s,`+"\n", jsonSiblings) // TMP
	fmt.Fprintf(w, `	"secretKey": "%s",`+"\n", secretKey.String())
	fmt.Fprintf(w, `	"voteValue": "%s",`+"\n", vote.String())
	fmt.Fprintf(w, `	"electionId": "%s",`+"\n", electionId.String())
	fmt.Fprintf(w, `	"nullifier": "%s"`+"\n", nullifier.String())
	fmt.Fprintln(w, "}")

	err = ioutil.WriteFile(inputsFileName, w.Bytes(), 0600)
	assert.Nil(t, err)
}
