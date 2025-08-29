package main

import (
	"encoding/json"
	"fmt"
	"os"

	"AurFingerprintAgent/fingerprint"
)

func main() {
	snap := fingerprint.GetSnapshot()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		fmt.Fprintln(os.Stderr, "encode error:", err)
		os.Exit(1)
	}
}
