// signer produces a BIP340 signature over a 32-byte sighash with a private
// key: `signer <privhex> <sighashhex>` -> 64-byte schnorr sig hex. It is the
// client-side signing step a wallet performs on the sighashes openampd
// returns from /v1/transfers (here for demos and tests).
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: signer <privhex> <sighashhex>")
		os.Exit(2)
	}
	priv, _ := hex.DecodeString(os.Args[1])
	var m [32]byte
	b, _ := hex.DecodeString(os.Args[2])
	copy(m[:], b)
	s, err := elements.SignSchnorr(priv, m)
	if err != nil {
		panic(err)
	}
	fmt.Print(hex.EncodeToString(s))
}
