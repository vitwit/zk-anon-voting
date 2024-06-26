package cmd

import (
	voting "anon-voting/circuit"
	"anon-voting/utils"
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var generateProofCmd = &cobra.Command{
	Use:   "generate-proof",
	Short: "Generate a proof",
	Run: func(cmd *cobra.Command, args []string) {
		userIdStr, _ := cmd.Flags().GetString("userId")
		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if userId <= 0 {
			fmt.Println("userId is required")
			return
		}

		userPath := strconv.FormatInt(userId, 10)
		commitment, err := utils.FetchInfo("commitment_" + userPath)
		if err != nil {
			fmt.Println("Error reading commitment", err)
			return
		}

		nullifier, err := utils.FetchInfo("nullifier_" + userPath)
		if err != nil {
			fmt.Println("Error reading nullifier", err)
			return
		}

		voterId, err := utils.FetchInfo("voterId_" + userPath)
		if err != nil {
			fmt.Println("Error reading voterId", err)
			return
		}

		var buf bytes.Buffer
		// build merkle proof
		dataSegments := 4
		proofIndex := 0
		dataSize := len(commitment)
		hFunc := mimc.NewMiMC()
		for j := byte(1); j <= byte(dataSegments); j++ {
			data := commitment
			hFunc.Reset()
			hFunc.Write(data)
			hash := hFunc.Sum(nil)

			_, err := buf.Write(hash)
			if err != nil {
				fmt.Println("failed to write hash", err)
			}
		}

		root, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, hFunc, dataSize, uint64(proofIndex))
		verified := merkletree.VerifyProof(hFunc, root, proof, uint64(proofIndex), numLeaves)
		if verified {
			fmt.Println("Proof is generated and verified")
		}

		// Define the inputs
		assignment := voting.Circuit{
			UniqueId1:   userId,
			ProofIndex:  0,
			UniqueId2:   voterId,
			Commitment:  commitment,
			Nullifier:   nullifier,
			MerkleProof: utils.GetMerkleProofFromBytes(root, proof),
			MerkleRoot:  root,
			VoteOption:  1,
		}
		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		publicWitness, err := witness.Public()

		if err != nil {
			fmt.Println("failed to generate witness", err.Error())
			return
		}
		err = utils.SaveInfo("witness_"+userPath, []byte(fmt.Sprintf("%v", publicWitness)))
		if err != nil {
			fmt.Println("Error writing nullifier to file:", err.Error())
			return
		}

	},
}

func init() {
	rootCmd.AddCommand(generateProofCmd)
	generateProofCmd.Flags().StringP("userId", "u", "", "Registered userId")
	viper.BindPFlag("userId", generateProofCmd.Flags().Lookup("userId"))
}
