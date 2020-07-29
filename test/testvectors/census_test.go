package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree"
	"github.com/iden3/go-merkletree/db/memory"
	"github.com/stretchr/testify/assert"
)

func TestCensus(t *testing.T) {
	testCensus(t, 3, 1, 0)
	testCensus(t, 9, 10, 10)
	testCensus(t, 19, 50, 1000)
}

func testCensus(t *testing.T, nLevels, nMiners, nPaddingLeafs int) {
	fmt.Println("\n-------\nCensus test vectors:")
	fmt.Printf("%d levels, %d miner, %d padding leafs\n", nLevels, nMiners, nPaddingLeafs)

	// new babyjubjub PrivateKey
	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}

	// new CensusTree
	censusTree, err := merkletree.NewMerkleTree(memory.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	keyHash, err := poseidon.Hash([poseidon.T]*big.Int{
		k.Public().X,
		k.Public().Y,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

	// add keyHash to CensusMerkleTree
	err = censusTree.Add(keyHash, big.NewInt(0))
	assert.Nil(t, err)

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingLeafs; i++ {
		err = censusTree.Add(big.NewInt(int64(i)), big.NewInt(int64(i)))
		assert.Nil(t, err)
	}

	// get merkleproof
	proof, err := censusTree.GenerateProof(keyHash, nil)
	assert.Nil(t, err)
	siblings := merkletree.SiblingsFromProof(proof)
	// for i := len(siblings); i < censusTree.MaxLevels(); i++ {
	for i := len(siblings); i < nLevels; i++ { // once mt.MaxLevels() is ready, use previous line
		siblings = append(siblings, &merkletree.HashZero)
	}
	siblings = append(siblings, &merkletree.HashZero)
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		siblingBytes := siblings[i].Bytes()
		siblingsStr = append(siblingsStr, new(big.Int).SetBytes(common3.SwapEndianness(siblingBytes[:])).String())
	}
	jsonSiblings, err := json.Marshal(siblingsStr)
	assert.Nil(t, err)

	// get CensusRoot
	// censusRoot := new(big.Int).SetBytes(common3.SwapEndianness(censusTree.RootKey().Bytes()))

	// sign vote with PrivateKey
	vote := big.NewInt(1)
	voteSig := k.SignPoseidon(vote)

	// compute nullifier
	electionId := big.NewInt(10)
	nullifier, err := poseidon.Hash([poseidon.T]*big.Int{
		babyjub.SkToBigInt(&k),
		electionId,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

	// relayerPublicKey & relayerProof
	relayerPublicKey := big.NewInt(100)
	relayerProof, err := poseidon.Hash([poseidon.T]*big.Int{
		nullifier,
		relayerPublicKey,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

	// revealKey & commitKey
	var revealKey []*big.Int
	var commitKey []*big.Int
	for i := 0; i < nMiners; i++ {
		rk := big.NewInt(int64(i))
		ck, err := poseidon.Hash([poseidon.T]*big.Int{
			rk,
			big.NewInt(0),
			big.NewInt(0),
			big.NewInt(0),
			big.NewInt(0),
			big.NewInt(0),
		})
		assert.Nil(t, err)

		revealKey = append(revealKey, rk)
		commitKey = append(commitKey, ck)
	}
	for i := 0; i < nMiners; i++ {

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

	rootBytes := censusTree.Root().Bytes()
	fmt.Println("--- copy & paste into census.test.js ---")
	fmt.Printf(`censusRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(rootBytes[:])))
	fmt.Printf(`censusSiblings: %s,`+"\n", jsonSiblings) // TMP
	fmt.Printf(`privateKey: "%s",`+"\n", babyjub.SkToBigInt(&k))

	fmt.Printf(`voteSigS: "%s",`+"\n", voteSig.S.String())
	fmt.Printf(`voteSigR8x: "%s",`+"\n", voteSig.R8.X.String())
	fmt.Printf(`voteSigR8y: "%s",`+"\n", voteSig.R8.Y.String())
	fmt.Printf(`voteValue: "%s",`+"\n", vote.String())
	fmt.Printf(`electionId: "%s",`+"\n", electionId.String())
	fmt.Printf(`nullifier: "%s",`+"\n", nullifier.String())
	fmt.Printf(`relayerPublicKey: "%s",`+"\n", relayerPublicKey.String())
	fmt.Printf(`relayerProof: "%s",`+"\n", relayerProof.String())
	fmt.Printf(`revealKey: %s,`+"\n", jsonRevealKey)
	fmt.Printf(`commitKey: %s`+"\n", jsonCommitKey)
	fmt.Println("--- end of copy & paste to census.test.js ---")

}
