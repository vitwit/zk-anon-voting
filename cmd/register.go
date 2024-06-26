package cmd

import (
	"anon-voting/utils"
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new Voter",
	Run: func(cmd *cobra.Command, args []string) {
		userId := viper.GetInt64("userId")
		if userId > 0 {
			fmt.Println("UserId is required")
			return
		}

		randomId := getRandomNumber()
		commitment, nullifier := createCommitmentAndNullifier(userId, randomId)

		cmtBuf, nulBuf := bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{})
		cmtBuf.Write(commitment)
		nulBuf.Write(nullifier)

		// store the above voterInfo
		userPath := strconv.FormatInt(userId, 10)
		err := utils.SaveInfo("commitment_"+userPath, cmtBuf.Bytes())
		if err != nil {
			fmt.Println("Error writing commitment to file:", err.Error())
			return
		}

		err = utils.SaveInfo("nullifier_"+userPath, nulBuf.Bytes())
		if err != nil {
			fmt.Println("Error writing nullifier to file:", err.Error())
			return
		}

		err = utils.SaveInfo("voterId_"+userPath, []byte(fmt.Sprintf("%d\n", randomId)))
		if err != nil {
			fmt.Println("Error writing to file:", err.Error())
			return
		}

	},
}

// Generate a random 5-digit salt
func getRandomNumber() int64 {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))

	return int64(rng.Intn(10000))
}

// To create a commitment and nullifier
func createCommitmentAndNullifier(userId, randomId int64) ([]byte, []byte) {
	hFunc := mimc.NewMiMC()

	// Create commitment
	hFunc.Write(big.NewInt(userId).Bytes())
	hFunc.Write(big.NewInt(randomId).Bytes())
	commitment := hFunc.Sum(nil)
	hFunc.Reset()

	// Create nullifier
	hFunc.Write(big.NewInt(randomId).Bytes())
	nullifier := hFunc.Sum(nil)

	return commitment, nullifier
}

func init() {
	rootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringP("userId", "u", "", "UserId for registration")
	viper.BindPFlag("userId", registerCmd.Flags().Lookup("userId"))
}
