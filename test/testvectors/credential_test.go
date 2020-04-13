package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
)

func pruneBuffer(buf *[32]byte) *[32]byte {
	buf[0] = buf[0] & 0xF8
	buf[31] = buf[31] & 0x7F
	buf[31] = buf[31] | 0x40
	return buf
}

func skToBigInt(k *babyjub.PrivateKey) *big.Int {
	sBuf := babyjub.Blake512(k[:])
	sBuf32 := [32]byte{}
	copy(sBuf32[:], sBuf[:32])
	pruneBuffer(&sBuf32)
	s := new(big.Int)
	cryptoUtils.SetBigIntFromLEBytes(s, sBuf32[:])
	s.Rsh(s, 3)
	return s
}

func TestCensus(t *testing.T) {
	fmt.Println("\n-------\nCensus test vectors:")

	nLevels := 3

	// new babyjubjub PrivateKey
	privKHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}

	// new CensusTree
	censusTree, err := merkletree.NewMerkleTree(db.NewMemoryStorage(), nLevels)
	assert.Nil(t, err)

	// put PublicKey to ClaimKeyBabyJub
	claim := claims.NewClaimKeyBabyJub(k.Public())

	// add ClaimKeyBabyJub to CensusMerkleTree
	err = censusTree.AddClaim(claim)
	assert.Nil(t, err)

	// get merkleproof
	// hiClaimAboutId, _ := claimAboutId.Entry().HIndex()
	// proof, err := clt.GenerateProof(hiClaimAboutId, nil)
	// assert.Nil(t, err)

	// get CensusRoot
	// censusRoot := new(big.Int).SetBytes(common3.SwapEndianness(censusTree.RootKey().Bytes()))

	// sign vote with PrivateKey

	fmt.Println("--- copy & paste into census.test.js ---")
	fmt.Printf(`censusRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(censusTree.RootKey().Bytes())))
	fmt.Printf(`censusSiblings: ["0", "0", "0", "0"],` + "\n") // TMP
	fmt.Printf(`privateKey: "%s",`+"\n", skToBigInt(&k))

	fmt.Printf(`voteSigS: "%s",`+"\n", "tmp")
	fmt.Printf(`voteSigR8x: "%s",`+"\n", "tmp")
	fmt.Printf(`voteSigR8y: "%s",`+"\n", "tmp")
	fmt.Printf(`voteValue: "%s",`+"\n", "tmp")
	fmt.Printf(`electionId: "%s",`+"\n", "tmp")
	fmt.Printf(`nullifier: "%s"`+"\n", "tmp")
	fmt.Println("--- end of copy & paste to census.test.js ---")

}
