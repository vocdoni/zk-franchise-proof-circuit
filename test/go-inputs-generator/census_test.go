package main

import (
	"bytes"
	"crypto/sha256"
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
	index := big.NewInt(0)

	secretKeyHashBI, err := poseidon.Hash([]*big.Int{
		secretKey,
	})
	bLen := arbo.HashFunctionPoseidon.Len()
	indexBytes := arbo.BigIntToBytes(bLen, index)
	secretKeyHashBytes := arbo.BigIntToBytes(bLen, secretKeyHashBI)

	// add keyHash to CensusMerkleTree
	err = censusTree.Add(indexBytes, secretKeyHashBytes)
	assert.Nil(t, err)
	userIndex := index
	index = new(big.Int).Add(index, big.NewInt(1))

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingLeafs; i++ {
		indexBytes := arbo.BigIntToBytes(bLen, index)
		err = censusTree.Add(
			indexBytes,
			arbo.BigIntToBytes(bLen, big.NewInt(int64(i))))
		assert.Nil(t, err)
		index = new(big.Int).Add(index, big.NewInt(1))
	}

	// get merkleproof
	userIndexBytes := arbo.BigIntToBytes(bLen, userIndex)
	proof, err := censusTree.GenProof(userIndexBytes, secretKeyHashBytes)
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
	voteValueHash := sha256.Sum256(vote.Bytes())
	voteValue0 := new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[:16])) // little-endian
	voteValue1 := new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[16:]))
	voteValue := fmt.Sprintf("[\"%s\", \"%s\"]", voteValue0.String(), voteValue1.String())

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
	fmt.Fprintf(w, `	"index": "%s",`+"\n", userIndex.String())
	fmt.Fprintf(w, `	"secretKey": "%s",`+"\n", secretKey.String())
	fmt.Fprintf(w, `	"voteValue": %s,`+"\n", voteValue)
	fmt.Fprintf(w, `	"electionId": "%s",`+"\n", electionId.String())
	fmt.Fprintf(w, `	"nullifier": "%s"`+"\n", nullifier.String())
	fmt.Fprintln(w, "}")

	err = ioutil.WriteFile(inputsFileName, w.Bytes(), 0600)
	assert.Nil(t, err)
}
