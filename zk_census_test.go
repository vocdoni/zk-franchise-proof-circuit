package zkfranchiseproofcircuit

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/zk-franchise-proof-circuit/internal"
	"go.vocdoni.io/dvote/crypto/zk/prover"
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

	inputs, err := internal.MockInputs(nLevels, 10)
	c.Assert(err, qt.IsNil)

	output := fmt.Sprintf("./artifacts/%s/%s/%d/inputs_example.json", name, env, nLevels)
	err = os.WriteFile(output, inputs.Bytes(), 0644)
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
