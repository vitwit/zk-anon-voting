package voting

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Define the circuit
type Circuit struct {
	UniqueId1  frontend.Variable
	ProofIndex frontend.Variable `gnark:",public"`
	UniqueId2  frontend.Variable
	Commitment frontend.Variable
	Nullifier  frontend.Variable `gnark:",public"`
	VoteOption frontend.Variable `gnark:",public"`
	//Signature   eddsa.Signature //todo
	MerkleProof merkle.MerkleProof
	MerkleRoot  frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	hashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	hashFunc.Write(circuit.UniqueId1, circuit.UniqueId2)
	commitment := hashFunc.Sum()

	// Ensure the commitment matches the provided commitment
	api.AssertIsEqual(commitment, circuit.Commitment)

	api.AssertIsEqual(circuit.MerkleProof.RootHash, circuit.MerkleRoot)

	// Hash the commitment to generate nullifier
	hashFunc.Reset()
	hashFunc.Write(circuit.UniqueId2)
	nullifier := hashFunc.Sum()

	// Comparing the circuit generated nullifier with provided nullifier
	api.AssertIsEqual(nullifier, circuit.Nullifier)
	hashFunc.Reset()
	circuit.MerkleProof.VerifyProof(api, &hashFunc, circuit.ProofIndex)

	//// Signature verification
	//curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	//if err != nil {
	//	return err
	//}
	//
	//hashFunc.Reset()
	//err = eddsa.Verify(curve, circuit.Signature, circuit.VoteOption, circuit.PubKey, &hashFunc)

	return err
}
