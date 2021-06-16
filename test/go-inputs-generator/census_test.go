package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/censustree/arbotree"
)

func TestCensus(t *testing.T) {
	testCensus(t, "inputs0.json", 3, 1, 0)
	testCensus(t, "inputs1.json", 9, 10, 10)
	testCensus(t, "inputs2.json", 19, 50, 1000)
}

func testCensus(t *testing.T, inputsFileName string, nLevels, nMiners, nPaddingLeafs int) {
	fmt.Printf("%d levels, %d miner, %d padding leafs\n", nLevels, nMiners, nPaddingLeafs)

	// --- User side
	// -------------
	// new babyjubjub PrivateKey
	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}

	// --- Org side
	// ------------
	// new CensusTree
	censusTree, err := arbotree.NewTree("test0", t.TempDir(), nLevels, arbo.HashFunctionBlake2b)
	assert.Nil(t, err)

	leafKeyBI, err := poseidon.Hash([]*big.Int{
		k.Public().X,
		k.Public().Y,
	})
	bLen := arbo.HashFunctionPoseidon.Len()
	leafKey := arbo.BigIntToBytes(bLen, leafKeyBI)

	// add keyHash to CensusMerkleTree
	err = censusTree.Add(leafKey, []byte{0})
	assert.Nil(t, err)

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingLeafs; i++ {
		err = censusTree.Add(
			arbo.BigIntToBytes(bLen, big.NewInt(int64(i))),
			arbo.BigIntToBytes(bLen, big.NewInt(int64(i))))
		assert.Nil(t, err)
	}

	// get merkleproof
	proof, err := censusTree.GenProof(leafKey, []byte{0})
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
	// sign vote with PrivateKey
	vote := big.NewInt(1)
	voteSig := k.SignPoseidon(vote)

	// compute nullifier
	electionId := big.NewInt(10)
	nullifier, err := poseidon.Hash([]*big.Int{
		babyjub.SkToBigInt(&k),
		electionId,
	})

	// relayerPublicKey & relayerProof
	relayerPublicKey := big.NewInt(100)
	relayerProof, err := poseidon.Hash([]*big.Int{
		nullifier,
		relayerPublicKey,
	})

	// revealKey & commitKey
	var revealKey []*big.Int
	var commitKey []*big.Int
	for i := 0; i < nMiners; i++ {
		rk := big.NewInt(int64(i))
		ck, err := poseidon.Hash([]*big.Int{
			rk,
		})
		assert.Nil(t, err)

		revealKey = append(revealKey, rk)
		commitKey = append(commitKey, ck)
	}
	var revealKeyStr []string
	var commitKeyStr []string
	for i := 0; i < nMiners; i++ {
		revealKeyStr = append(revealKeyStr, revealKey[i].String())
		commitKeyStr = append(commitKeyStr, commitKey[i].String())
	}
	jsonRevealKey, err := json.Marshal(revealKeyStr)
	assert.Nil(t, err)
	jsonCommitKey, err := json.Marshal(commitKeyStr)
	assert.Nil(t, err)

	w := bytes.NewBufferString("")
	fmt.Fprintf(w, "{\n")
	fmt.Fprintf(w, `	"censusRoot": "%s",`+"\n", arbo.BytesToBigInt(rootBytes[:]))
	fmt.Fprintf(w, `	"censusSiblings": %s,`+"\n", jsonSiblings) // TMP
	fmt.Fprintf(w, `	"privateKey": "%s",`+"\n", babyjub.SkToBigInt(&k))
	fmt.Fprintf(w, `	"voteSigS": "%s",`+"\n", voteSig.S.String())
	fmt.Fprintf(w, `	"voteSigR8x": "%s",`+"\n", voteSig.R8.X.String())
	fmt.Fprintf(w, `	"voteSigR8y": "%s",`+"\n", voteSig.R8.Y.String())
	fmt.Fprintf(w, `	"voteValue": "%s",`+"\n", vote.String())
	fmt.Fprintf(w, `	"electionId": "%s",`+"\n", electionId.String())
	fmt.Fprintf(w, `	"nullifier": "%s",`+"\n", nullifier.String())
	fmt.Fprintf(w, `	"relayerPublicKey": "%s",`+"\n", relayerPublicKey.String())
	fmt.Fprintf(w, `	"relayerProof": "%s",`+"\n", relayerProof.String())
	fmt.Fprintf(w, `	"revealKey": %s,`+"\n", jsonRevealKey)
	fmt.Fprintf(w, `	"commitKey": %s`+"\n", jsonCommitKey)
	fmt.Fprintln(w, "}")

	err = ioutil.WriteFile(inputsFileName, w.Bytes(), 0600)
	assert.Nil(t, err)
}
