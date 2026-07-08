// keygen prints demo BIP340 keypairs (name, privkey, x-only pubkey) for
// exercising openampd. Testnet/demo use only; production keys never touch this.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/elements"
)

func main() {
	for _, n := range []string{"issuer", "alice", "bob"} {
		p := make([]byte, 32)
		rand.Read(p)
		x := elements.XOnlyFromPriv(p)
		fmt.Printf("%s %s %s\n", n, hex.EncodeToString(p), hex.EncodeToString(x[:]))
	}
}
