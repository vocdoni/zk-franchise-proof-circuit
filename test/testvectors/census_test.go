package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	common3 "github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
)

func TestCensus(t *testing.T) {
	testCensus(t, 3, 1, 0)
	testCensus(t, 9, 10, 10)
	testCensus(t, 19, 50, 1000)
}

func testCensus(t *testing.T, nLevels, nMiners, nPaddingClaims int) {
	fmt.Println("\n-------\nCensus test vectors:")

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
	claim := claims.NewClaimKeyBabyJub(k.Public(), 0)

	// add ClaimKeyBabyJub to CensusMerkleTree
	err = censusTree.AddClaim(claim)
	assert.Nil(t, err)

	// add extra claims to fill the MerkleTree
	for i := 0; i < nPaddingClaims; i++ {
		indexData := []byte("padding-claim-" + strconv.Itoa(i))
		valueData := []byte("padding-claim-" + strconv.Itoa(i))
		var indexSlot [claims.IndexSlotLen]byte
		var valueSlot [claims.ValueSlotLen]byte
		copy(indexSlot[:], indexData[:])
		copy(valueSlot[:], valueData[:])
		c := claims.NewClaimBasic(indexSlot, valueSlot)
		err = censusTree.AddClaim(c)
		assert.Nil(t, err)
	}

	// get merkleproof
	hi, _ := claim.Entry().HIndex()
	proof, err := censusTree.GenerateProof(hi, nil)
	assert.Nil(t, err)
	siblings := merkletree.SiblingsFromProof(proof)
	for i := len(siblings); i < censusTree.MaxLevels(); i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	siblings = append(siblings, &merkletree.HashZero)
	var siblingsStr []string
	for i := 0; i < len(siblings); i++ {
		siblingsStr = append(siblingsStr, new(big.Int).SetBytes(common3.SwapEndianness(siblings[i].Bytes())).String())
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
	nullifier, err := poseidon.PoseidonHash([poseidon.T]*big.Int{
		skToBigInt(&k),
		electionId,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

	// relayerPublicKey & relayerProof
	relayerPublicKey := big.NewInt(100)
	relayerProof, err := poseidon.PoseidonHash([poseidon.T]*big.Int{
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
		ck, err := poseidon.PoseidonHash([poseidon.T]*big.Int{
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

	fmt.Println("--- copy & paste into census.test.js ---")
	fmt.Printf(`censusRoot: "%s",`+"\n", new(big.Int).SetBytes(common3.SwapEndianness(censusTree.RootKey().Bytes())))
	fmt.Printf(`censusSiblings: %s,`+"\n", jsonSiblings) // TMP
	fmt.Printf(`privateKey: "%s",`+"\n", skToBigInt(&k))

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
