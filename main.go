package main

import (
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
	fmt.Println(b)
}
