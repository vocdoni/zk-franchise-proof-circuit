package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"

	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/crypto/zk"
	"go.vocdoni.io/dvote/crypto/zk/prover"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
)

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

	// Generate the ZkAddress
	needlePrivateKey := "6430ab787ad5130942369901498a118fade013ebab5450efbfb6acac66d8fb88"
	zkAddr, err := zk.AddressFromString(needlePrivateKey)
	c.Assert(err, qt.IsNil)

	// Create a census tree
	database, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	censusTree, err := arbo.NewTree(arbo.Config{
		Database:     database,
		MaxLevels:    nLevels,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Define a weight and add it with the public key to the census
	votingWeight := new(big.Int).SetInt64(20)
	factoryWeight := new(big.Int).SetInt64(255)
	err = censusTree.Add(zkAddr.Bytes(), factoryWeight.Bytes())
	c.Assert(err, qt.IsNil)

	// Add extra voters to the census
	for i := 0; i < nPaddingLeafs; i++ {
		mockZkAddr, err := zk.NewRandAddress()
		c.Assert(err, qt.IsNil)

		err = censusTree.Add(mockZkAddr.Bytes(), factoryWeight.Bytes())
		c.Assert(err, qt.IsNil)
	}

	// Get the CensusProof => {key, value, siblings}
	leafKey, leafValue, packedSiblings, exists, err := censusTree.GenProof(zkAddr.Bytes())
	c.Assert(leafKey, qt.ContentEquals, []byte(zkAddr.Bytes()))
	c.Assert(leafValue, qt.DeepEquals, factoryWeight.Bytes())
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
	voteHash := zk.BytesToArboStr(factoryWeight.Bytes())

	// Define the ProcessId
	electionId, _ := hex.DecodeString("c5d2460186f760d51371516148fd334b4199052f01538553aa9a020200000000")
	processId := zk.BytesToArboStr(electionId)

	// Compute the Nullifier privKey + processId
	nullifier, err := zkAddr.Nullifier(electionId)
	c.Assert(err, qt.IsNil)

	// Write the result using string templating to keep the key order
	result := map[string]any{
		"processId":      processId,
		"censusRoot":     strCensusRoot,
		"censusSiblings": strSiblings,
		"voteHash":       voteHash,
		"votingWeight":   votingWeight.String(),
		"factoryWeight":  factoryWeight.String(),
		"privateKey":     zkAddr.PrivKey.String(),
		"nullifier":      nullifier.String(),
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
