package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"os"
	"path/filepath"
)

// To save voter info
func SaveInfo(filename string, data []byte) error {
	return os.WriteFile(filepath.Join("voters", filename), data, 0666)
}

// to fetch voter info
func FetchInfo(filename string) ([]byte, error) {
	info, err := os.ReadFile(filepath.Join("voters", filename))
	return info, err
}

// to get merkle proof from root+proof bytes
func GetMerkleProofFromBytes(rootBytes []byte, proofBytes [][]byte) merkle.MerkleProof {
	var merkleProof merkle.MerkleProof
	merkleProof.RootHash = rootBytes
	merkleProof.Path = make([]frontend.Variable, len(proofBytes))
	for i := 0; i < len(proofBytes); i++ {
		merkleProof.Path[i] = proofBytes[i]
	}
	return merkleProof
}
