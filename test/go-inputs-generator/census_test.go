package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db"
)

func TestCensus(t *testing.T) {
	testCensus(t, "inputs0.json", 4, 0)
	testCensus(t, "inputs1.json", 10, 10)
	testCensus(t, "inputs2.json", 20, 1000)
}

func testCensus(t *testing.T, inputsFileName string, nLevels, nPaddingLeafs int) {
	fmt.Printf("%d levels, %d padding leafs\n", nLevels, nPaddingLeafs)

	// --- User side
	// -------------
	// new babyjubjub PrivateKey
	var privateKeyStr = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var privateKey babyjub.PrivateKey
	if _, err := hex.Decode(privateKey[:], []byte(privateKeyStr)); err != nil {
		panic(err)
	}

	// --- Org side
	// ------------
	// new CensusTree
	database, err := db.NewBadgerDB(t.TempDir())
	assert.Nil(t, err)

	censusTree, err := arbo.NewTree(database, nLevels, arbo.HashFunctionPoseidon)
	assert.Nil(t, err)

	var weight = new(big.Int).SetInt64(1)
	publicKeyHash, err := poseidon.Hash([]*big.Int{
		privateKey.Public().X,
		privateKey.Public().Y,
	})
	assert.Nil(t, err)

	var bLen = arbo.HashFunctionPoseidon.Len()
	var weightBytes = arbo.BigIntToBytes(bLen, weight)
	var publicKeyHashBytes = arbo.BigIntToBytes(bLen, publicKeyHash)

	// add publicKeyHash to CensusMerkleTree
	err = censusTree.Add(publicKeyHashBytes, weightBytes)
	assert.Nil(t, err)

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingLeafs; i++ {
		var newWeight = arbo.BigIntToBytes(bLen, big.NewInt(int64(i+1)))
		var mockPublicKey = arbo.BigIntToBytes(bLen, big.NewInt(int64(i)))

		err = censusTree.Add(mockPublicKey, newWeight)
		assert.Nil(t, err)
	}

	// get merkleproof
	leafKey, leafValue, packedSiblings, exists, err := censusTree.GenProof(publicKeyHashBytes)
	assert.ElementsMatch(t, publicKeyHashBytes, leafKey)
	assert.ElementsMatch(t, weightBytes, leafValue)
	assert.True(t, exists)
	assert.Nil(t, err)

	// get siblings list
	siblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	assert.Nil(t, err)
	for i := len(siblings); i < nLevels; i++ {
		siblings = append(siblings, []byte{0})
	}
	siblings = append(siblings, []byte{0})
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		var sibling = arbo.BytesToBigInt(siblings[i]).String()
		siblingsStr = append(siblingsStr, sibling)
	}
	jsonSiblings, err := json.Marshal(siblingsStr)
	assert.Nil(t, err)

	// get CensusRoot
	rootBytes := censusTree.Root()

	// --- User side
	// -------------
	vote := big.NewInt(1)
	voteValueHash := sha256.Sum256(vote.Bytes())
	voteHash0 := new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[:16])) // little-endian
	voteHash1 := new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[16:]))
	voteHash := fmt.Sprintf("[\"%s\", \"%s\"]", voteHash0.String(), voteHash1.String())

	// compute nullifier
	processIdBytes := sha256.Sum256(big.NewInt(10).Bytes())
	processId := []*big.Int{
		new(big.Int).SetBytes(arbo.SwapEndianness(processIdBytes[:16])),
		new(big.Int).SetBytes(arbo.SwapEndianness(processIdBytes[16:])),
	}
	processIdStr := fmt.Sprintf("[\"%s\", \"%s\"]", processId[0].String(), processId[1].String())
	nullifier, err := poseidon.Hash([]*big.Int{
		babyjub.SkToBigInt(&privateKey),
		processId[0],
		processId[1],
	})
	assert.Nil(t, err)

	w := bytes.NewBufferString("")
	fmt.Fprintf(w, "{\n")
	fmt.Fprintf(w, `	"censusRoot": "%s",`+"\n", arbo.BytesToBigInt(rootBytes))
	fmt.Fprintf(w, `	"censusSiblings": %s,`+"\n", jsonSiblings) // TMP
	fmt.Fprintf(w, `	"weight": "%s",`+"\n", weight.String())
	fmt.Fprintf(w, `	"privateKey": "%s",`+"\n", babyjub.SkToBigInt(&privateKey))
	fmt.Fprintf(w, `	"voteHash": %s,`+"\n", voteHash)
	fmt.Fprintf(w, `	"processId": %s,`+"\n", processIdStr)
	fmt.Fprintf(w, `	"nullifier": "%s"`+"\n", nullifier.String())
	fmt.Fprintln(w, "}")

	err = os.WriteFile(inputsFileName, w.Bytes(), 0600)
	assert.Nil(t, err)
}
