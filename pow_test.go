package sphinx

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var powThreshold *big.Int

func TestPowGeneration(t *testing.T) {
	t.Parallel()
	threshold := []byte{31, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // Three leading zeros
	powThreshold = new(big.Int).SetBytes(threshold)
	for pathLength := 1; pathLength < 11; pathLength++ {
		pathPublicKeys := createPathPublicKeys(t, pathLength)
		t.Logf("starting path length: %d", pathLength)
		tries := generatePOWForPathLength(t, pathPublicKeys)
		t.Logf("path length: %d, tries: %d", pathLength, tries)
	}
}

func generatePOWForPathLength(t *testing.T, pathPublicKeys []*secp256k1.PublicKey) int {
	tries := 0
	for {
		tries++
		success := attemptPow(t, pathPublicKeys)
		if success {
			break
		}
	}
	return tries
}

func attemptPow(t *testing.T, pathPublicKeys []*secp256k1.PublicKey) bool {
	sourcePriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Errorf("unable to create private key: %v", err)
	}

	sharedSecrets, err := generateSharedSecrets(pathPublicKeys, sourcePriv)
	if err != nil {
		t.Errorf("unable to generate shared secrets: %v", err)
	}

	for _, sharedSecret := range sharedSecrets {
		hashInt := *new(big.Int).SetBytes(sharedSecret[:])
		if hashInt.Cmp(powThreshold) > 0 {
			return false
		}
	}

	return true
}

func createPathPublicKeys(t *testing.T, pathLength int) []*secp256k1.PublicKey {
	path := make([]*secp256k1.PublicKey, pathLength)
	for i := 0; i < pathLength; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Errorf("unable to create private key: %v", err)
		}

		pub := priv.PubKey()
		path[i] = pub
	}
	return path
}
