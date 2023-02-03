package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/crypto/zk/prover"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/badgerdb"
	"go.vocdoni.io/dvote/tree/arbo"
)

func truncate(input *big.Int, to int64) (*big.Int, int64) {
	var nBytes = numberOfBytes(input)
	if nBytes <= to {
		return input, 0
	}

	var timesShifted int64 = 0
	var bTen = new(big.Int).SetInt64(10)
	for nBytes != to {
		input = input.Div(input, bTen)
		nBytes = numberOfBytes(input)
		timesShifted++
	}

	return input, timesShifted
}

func numberOfBytes(input *big.Int) int64 {
	var nBits int64 = 0
	base := new(big.Int).SetInt64(2)
	candidate := new(big.Int).Exp(base, big.NewInt(nBits), nil)
	for input.Cmp(candidate) == 1 {
		nBits++
		candidate = candidate.Exp(base, big.NewInt(nBits), nil)
	}

	return nBits/8 + 1
}

func getEnvVars(t *testing.T) (string, string, int, int, int) {
	circuitName, environment, nLevels, keySize, nPaddingLeafs := "zkCensus", "dev", 160, 20, 100

	circuitNameVar := os.Getenv("CIRCUIT_NAME")
	if circuitNameVar != "" {
		circuitName = circuitNameVar
	}

	envVar := os.Getenv("ENVIRONMENT")
	if envVar != "" {
		environment = envVar
	}

	nLevelsVar := os.Getenv("NLEVELS")
	if numNLevels, err := strconv.Atoi(nLevelsVar); err == nil {
		if numNLevels < 10 {
			t.Fatal("the number of levels must be 10 at least to support the current key length")
		}

		nLevels = numNLevels
	}

	keySizeVar := os.Getenv("KEYSIZE")
	if numKeySize, err := strconv.Atoi(keySizeVar); err == nil {
		if numKeySize > nLevels/8 {
			t.Fatal("the key size can not be bigger than ceil(nLevels/8)")
		}

		keySize = numKeySize
	}

	nPaddingLeafsVar := os.Getenv("PADDING")
	if numPaddingLeafs, err := strconv.Atoi(nPaddingLeafsVar); err == nil {
		nPaddingLeafs = numPaddingLeafs
	}

	return circuitName, environment, nLevels, keySize, nPaddingLeafs
}

func Test_genInputs(t *testing.T) {
	t.Log("Generating example of circuits inputs...")
	c := qt.New(t)

	name, env, nLevels, keySize, nPaddingLeafs := getEnvVars(t)
	t.Logf("Config loaded:%v\n", map[string]interface{}{
		"name":          name,
		"env":           env,
		"nLevels":       nLevels,
		"keySize":       keySize,
		"nPaddingLeafs": nPaddingLeafs,
	})

	// Generate babyjubjub keys
	needlePrivateKey := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"
	privateKey := babyjub.PrivateKey{}
	_, err := hex.Decode(privateKey[:], []byte(needlePrivateKey))
	c.Assert(err, qt.IsNil)

	// Create a census tree
	database, err := badgerdb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	censusTree, err := arbo.NewTree(arbo.Config{
		Database:     database,
		MaxLevels:    nLevels,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Define a weight and add it with the public key to the census
	weight := new(big.Int).SetInt64(1)
	pubKey, err := poseidon.Hash([]*big.Int{
		privateKey.Public().X,
		privateKey.Public().Y,
	})
	c.Assert(err, qt.IsNil)

	truncatedPubKey, timesShifted := truncate(pubKey, int64(keySize))
	bWeight := arbo.BigIntToBytes(keySize, weight)
	bPubKey := arbo.BigIntToBytes(keySize, truncatedPubKey)

	err = censusTree.Add(bPubKey, bWeight)
	c.Assert(err, qt.IsNil)
	strWeight := weight.String()
	strPrivKey := babyjub.SkToBigInt(&privateKey).String()

	// Add extra voters to the census
	for i := 0; i < nPaddingLeafs; i++ {
		weight := arbo.BigIntToBytes(keySize, big.NewInt(int64(i+1)))
		mockPublicKey := arbo.BigIntToBytes(keySize, big.NewInt(int64(i)))

		err = censusTree.Add(mockPublicKey, weight)
		c.Assert(err, qt.IsNil)
	}

	// Get the CensusProof => {key, value, siblings}
	leafKey, leafValue, packedSiblings, exists, err := censusTree.GenProof(bPubKey)
	c.Assert(leafKey, qt.DeepEquals, bPubKey)
	c.Assert(leafValue, qt.DeepEquals, bWeight)
	c.Assert(exists, qt.IsTrue)
	c.Assert(err, qt.IsNil)

	currentSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	c.Assert(err, qt.IsNil)
	strSiblings := make([]string, nLevels+1)
	for i := 0; i < len(strSiblings); i++ {
		strSibling := "0"
		if i < len(currentSiblings) {
			strSibling = arbo.BytesToBigInt(currentSiblings[i]).String()
		}
		strSiblings[i] = strSibling
	}

	// Get the CensusRoot
	censusRoot, err := censusTree.Root()
	c.Assert(err, qt.IsNil)
	strCensusRoot := arbo.BytesToBigInt(censusRoot).String()

	// Compute the VoteHash
	voteValue := big.NewInt(1)
	voteValueHash := sha256.Sum256(voteValue.Bytes())
	strVoteHash := []string{
		new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[:16])).String(),
		new(big.Int).SetBytes(arbo.SwapEndianness(voteValueHash[16:])).String(),
	}

	// Define the ProcessId
	processIdValue := sha256.Sum256(big.NewInt(10).Bytes())
	processId := []*big.Int{
		new(big.Int).SetBytes(arbo.SwapEndianness(processIdValue[:16])),
		new(big.Int).SetBytes(arbo.SwapEndianness(processIdValue[16:])),
	}
	strProcessId := []string{
		processId[0].String(),
		processId[1].String(),
	}

	// Compute the Nullifier privKey + processId
	nullifier, err := poseidon.Hash([]*big.Int{
		babyjub.SkToBigInt(&privateKey),
		processId[0],
		processId[1],
	})
	c.Assert(err, qt.IsNil)
	strNullifier := nullifier.String()

	// Write the result using string templating to keep the key order
	result := map[string]any{
		"censusRoot":     strCensusRoot,
		"censusSiblings": strSiblings,
		"weight":         strWeight,
		"privateKey":     strPrivKey,
		"voteHash":       strVoteHash,
		"processId":      strProcessId,
		"nullifier":      strNullifier,
		"shifted":        fmt.Sprint(timesShifted),
	}

	jsonResult, err := json.Marshal(result)
	c.Assert(err, qt.IsNil)

	output := fmt.Sprintf("./artifacts/%s/%s/%d/inputs_example.json", name, env, nLevels)
	err = os.WriteFile(output, jsonResult, 0644)
	c.Assert(err, qt.IsNil)
}

func Test_genProof(t *testing.T) {
	t.Log("Generating proof for the circuit...")

	name, env, nLevels, _, _ := getEnvVars(t)
	basePath := fmt.Sprintf("./artifacts/%s/%s/%d", name, env, nLevels)

	// Get files
	zkey, err := os.ReadFile(basePath + "/proving_key.zkey")
	qt.Assert(t, err, qt.IsNil)
	wasm, err := os.ReadFile(basePath + "/circuit.wasm")
	qt.Assert(t, err, qt.IsNil)
	inputs, err := os.ReadFile(basePath + "/inputs_example.json")
	qt.Assert(t, err, qt.IsNil)

	// Generate the proof
	proof, err := prover.Prove(zkey, wasm, inputs)
	qt.Assert(t, err, qt.IsNil)

	// Encode proof and public signals
	proofData, pubSignals, err := proof.Bytes()
	qt.Assert(t, err, qt.IsNil)

	// Write encoded proof and public signals
	err = os.WriteFile(basePath+"/proof.json", proofData, 0644)
	qt.Assert(t, err, qt.IsNil)
	err = os.WriteFile(basePath+"/signals.json", pubSignals, 0644)
	qt.Assert(t, err, qt.IsNil)
}

func Test_verifyProof(t *testing.T) {
	t.Log("Verifiying proof of the circuit...")

	name, env, nLevels, _, _ := getEnvVars(t)
	basePath := fmt.Sprintf("./artifacts/%s/%s/%d", name, env, nLevels)

	// Get files
	vkey, err := os.ReadFile(basePath + "/verification_key.json")
	qt.Assert(t, err, qt.IsNil)
	proofData, err := os.ReadFile(basePath + "/proof.json")
	qt.Assert(t, err, qt.IsNil)
	pubSignals, err := os.ReadFile(basePath + "/signals.json")
	qt.Assert(t, err, qt.IsNil)

	// Parse proof
	proof, err := prover.ParseProof(proofData, pubSignals)
	qt.Assert(t, err, qt.IsNil)

	// Verify proof
	err = proof.Verify(vkey)
	qt.Assert(t, err, qt.IsNil)
}
