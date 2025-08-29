package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"AurFingerprintAgent/fingerprint"
)

func main() {
	snap := fingerprint.GetSnapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snapshot error:", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(b)
	fmt.Println(hex.EncodeToString(sum[:]))
}
