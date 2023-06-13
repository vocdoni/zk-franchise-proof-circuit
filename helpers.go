package zkfranchiseproofcircuit

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

var modulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

func BytesToFF(v []byte) *big.Int {
	z := big.NewInt(0)
	iv := new(big.Int).SetBytes(v)

	if c := iv.Cmp(modulus); c == 0 {
		return z
	} else if c != 1 && iv.Cmp(z) != -1 {
		return iv
	}

	return z.Mod(iv, modulus)

}

func BytesToArbo(input []byte) [2]*big.Int {
	hash := sha256.Sum256(input)
	return [2]*big.Int{
		new(big.Int).SetBytes(arbo.SwapEndianness(hash[:16])),
		new(big.Int).SetBytes(arbo.SwapEndianness(hash[16:])),
	}
}

func GenTree(dbName string, key, value []byte, n int) (*big.Int, *big.Int, [160]*big.Int, error) {
	dbTemp, err := os.MkdirTemp("", dbName)
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}
	database, err := pebbledb.New(db.Options{Path: dbTemp})
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}

	tree, err := arbo.NewTree(arbo.Config{
		Database:     database,
		MaxLevels:    160,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}

	if err := tree.Add(key, value); err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}

	for i := 1; i < n; i++ {
		err = tree.Add(util.RandomBytes(20), big.NewInt(1).Bytes())
		if err != nil {
			return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
		}
	}

	_, _, pSiblings, exist, err := tree.GenProof(key)
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	} else if !exist {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, fmt.Errorf("key does not exists")
	}

	uSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, pSiblings)
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}

	siblings := [160]*big.Int{}
	for i := 0; i < 160; i++ {
		if i < len(uSiblings) {
			siblings[i] = arbo.BytesToBigInt(uSiblings[i])
		} else {
			siblings[i] = big.NewInt(0)
		}
	}

	root, err := tree.Root()
	if err != nil {
		return big.NewInt(0), big.NewInt(0), [160]*big.Int{}, err
	}

	return arbo.BytesToBigInt(root), new(big.Int).SetInt64(int64(len(uSiblings))), siblings, nil
}
