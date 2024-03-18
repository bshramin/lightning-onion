package sphinx

import (
	"math/big"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)


func TestPowGeneration(t *testing.T) {
	t.Parallel()
	threshold1 := []byte{31, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // Three leading zeros
	threshold2 := []byte{15, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // Four leading zeros
	threshold3 := []byte{7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}  // Five leading zeros
	thresholds := [][]byte{threshold1, threshold2, threshold3}
	numOfRuns := 5
	wg := &sync.WaitGroup{}

	for thresholdIndex, threshold := range thresholds {
		wg.Add(1)
		go runForThreshold(t, wg, thresholdIndex, threshold, numOfRuns)
	}
	wg.Wait()
}

func runForThreshold(t *testing.T, wg *sync.WaitGroup, thresholdIndex int, threshold []byte, numOfRuns int) {
	defer wg.Done()
	powThreshold := new(big.Int).SetBytes(threshold)
	for pathLength := 1; pathLength < 9; pathLength++ {
		wg.Add(1)
		go runForPathLength(t, wg, thresholdIndex, powThreshold, pathLength, numOfRuns)
	}
}

func runForPathLength(t *testing.T, wg *sync.WaitGroup, thresholdIndex int, powThreshold *big.Int, pathLength int, numOfRuns int) {
	defer wg.Done()
	totalTries := 0
	for i := 0; i < numOfRuns; i++ {
		pathPublicKeys := createPathPublicKeys(t, pathLength)
		totalTries += generatePOWForPathLength(t, powThreshold, pathPublicKeys)
	}
	tries := totalTries / numOfRuns
	t.Logf("threshold: %d, path length: %d, tries: %d", thresholdIndex, pathLength, tries)
}

func generatePOWForPathLength(t *testing.T, powThreshold *big.Int, pathPublicKeys []*secp256k1.PublicKey) int {
	tries := 0
	for {
		tries++
		success := attemptPow(t, powThreshold, pathPublicKeys)
		if success {
			break
		}
	}
	return tries
}

func attemptPow(t *testing.T, powThreshold *big.Int, pathPublicKeys []*secp256k1.PublicKey) bool {
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
